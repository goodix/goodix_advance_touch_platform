#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/regulator/consumer.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/acpi.h>
#include <linux/spi/spi.h>

#include "main.h"
#include "hid.h"

bool debug_log_flag = true;


#ifdef CONFIG_ACPI
static inline int goodix_ts_acpi_pdata(struct device *dev,
		struct goodix_ts_core *cd)
{
	struct gpio_desc *desc;

	cd->data_report_reg = 0x1F6EC;// TODO get this from dsdt

#if (AVDD_LDO_CTRL_ENABLE)
	cd->avdd = devm_regulator_get(dev, "avdd");
	if (IS_ERR_OR_NULL(cd->avdd)) {
		ret = PTR_ERR(cd->avdd);
		ts_err("Failed to get regulator avdd:%d", ret);
		cd->avdd = NULL;
		return ret;
	}
#endif

	ts_info("try get data from acpi");
	desc = devm_gpiod_get_index(dev, NULL, 0, GPIOD_IN);
	if (IS_ERR(desc)) {
		ts_err("failed get irq gpio %ld", PTR_ERR(desc));
		return -EINVAL;
	}
	cd->irq_gpiod = desc;

	desc = devm_gpiod_get_index(dev, NULL, 1, GPIOD_OUT_LOW);
	if (IS_ERR(desc))
		ts_err("no valid reset gpio");
	else
		cd->reset_gpiod = desc;

	ts_info("[ACPI]irq gpio %d, reset gpio %d",
		desc_to_gpio(cd->irq_gpiod), desc_to_gpio(cd->reset_gpiod));

	return 0;
}
#else
static inline int goodix_ts_acpi_pdata(struct device *dev,
		struct goodix_ts_core *cd)
{
	return -ENODEV;
}
#endif

#define SPI_TRANS_PREFIX_LEN    1
#define REGISTER_WIDTH          4
#define SPI_READ_DUMMY_LEN      4
#define SPI_READ_PREFIX_LEN  \
		(SPI_TRANS_PREFIX_LEN + REGISTER_WIDTH + SPI_READ_DUMMY_LEN)
#define SPI_WRITE_PREFIX_LEN (SPI_TRANS_PREFIX_LEN + REGISTER_WIDTH)

#define SPI_WRITE_FLAG  0xF0
#define SPI_READ_FLAG   0xF1
int goodix_spi_read(struct goodix_ts_core *cd, unsigned int addr,
	unsigned char *data, unsigned int len)
{
	struct spi_device *spi = to_spi_device(&cd->spi->dev);
	u8 *rx_buf = NULL;
	u8 *tx_buf = NULL;
	struct spi_transfer xfers;
	struct spi_message spi_msg;
	int ret = 0;

	rx_buf = kzalloc(SPI_READ_PREFIX_LEN - 1 + len, GFP_KERNEL);
	tx_buf = kzalloc(SPI_READ_PREFIX_LEN - 1 + len, GFP_KERNEL);
	if (!rx_buf || !tx_buf) {
		ts_err("alloc tx/rx_buf failed, size:%d",
			SPI_READ_PREFIX_LEN - 1 + len);
		return -ENOMEM;
	}

	spi_message_init(&spi_msg);
	memset(&xfers, 0, sizeof(xfers));

	/*spi_read tx_buf format: 0xF1 + addr(4bytes) + data*/
	tx_buf[0] = SPI_READ_FLAG;
	tx_buf[1] = (addr >> 24) & 0xFF;
	tx_buf[2] = (addr >> 16) & 0xFF;
	tx_buf[3] = (addr >> 8) & 0xFF;
	tx_buf[4] = addr & 0xFF;
	tx_buf[5] = 0xFF;
	tx_buf[6] = 0xFF;
	tx_buf[7] = 0xFF;

	xfers.tx_buf = tx_buf;
	xfers.rx_buf = rx_buf;
	xfers.len = SPI_READ_PREFIX_LEN - 1 + len;
	xfers.cs_change = 0;
	spi_message_add_tail(&xfers, &spi_msg);
	ret = spi_sync(spi, &spi_msg);
	if (ret < 0) {
		ts_err("spi transfer error:%d", ret);
		goto exit;
	}
	memcpy(data, &rx_buf[SPI_READ_PREFIX_LEN - 1], len);

exit:
	kfree(rx_buf);
	kfree(tx_buf);
	return ret;
}

/**
 * goodix_spi_write- write device register through spi bus
 * @dev: pointer to device data
 * @addr: register address
 * @data: write buffer
 * @len: bytes to write
 * return: 0 - write ok; < 0 - spi transter error.
 */
int goodix_spi_write(struct goodix_ts_core *cd, unsigned int addr,
		unsigned char *data, unsigned int len)
{
	struct spi_device *spi = to_spi_device(&cd->spi->dev);
	u8 *tx_buf = NULL;
	struct spi_transfer xfers;
	struct spi_message spi_msg;
	int ret = 0;

	tx_buf = kzalloc(SPI_WRITE_PREFIX_LEN + len, GFP_KERNEL);
	if (!tx_buf)
		return -ENOMEM;

	spi_message_init(&spi_msg);
	memset(&xfers, 0, sizeof(xfers));

	tx_buf[0] = SPI_WRITE_FLAG;
	tx_buf[1] = (addr >> 24) & 0xFF;
	tx_buf[2] = (addr >> 16) & 0xFF;
	tx_buf[3] = (addr >> 8) & 0xFF;
	tx_buf[4] = addr & 0xFF;
	memcpy(&tx_buf[SPI_WRITE_PREFIX_LEN], data, len);
	xfers.tx_buf = tx_buf;
	xfers.len = SPI_WRITE_PREFIX_LEN + len;
	xfers.cs_change = 0;
	spi_message_add_tail(&xfers, &spi_msg);
	ret = spi_sync(spi, &spi_msg);
	if (ret < 0)
		ts_err("spi transfer error:%d", ret);

	kfree(tx_buf);
	return ret;
}

#define DEV_CONFIRM_VAL				0xAA
#define BOOTOPTION_ADDR				0x10000
static int brl_dev_confirm(struct goodix_ts_core *cd)
{
	int ret = 0;
	int retry = GOODIX_RETRY_3;
	u8 tx_buf[8] = {0};
	u8 rx_buf[8] = {0};

	memset(tx_buf, DEV_CONFIRM_VAL, sizeof(tx_buf));
	while (retry--) {
		ret = goodix_spi_write(cd, BOOTOPTION_ADDR,
			tx_buf, sizeof(tx_buf));
		if (ret < 0)
			return ret;
		ret = goodix_spi_read(cd, BOOTOPTION_ADDR,
			rx_buf, sizeof(rx_buf));
		if (ret < 0)
			return ret;
		if (!memcmp(tx_buf, rx_buf, sizeof(tx_buf)))
			break;
		usleep_range(5000, 5100);
	}

	if (retry < 0) {
		ts_err("device confirm failed, rx_buf:%*ph", 8, rx_buf);
		return -EINVAL;
	}

	ts_info("device connected");
	return ret;
}

#define GOODIX_NORMAL_RESET_DELAY_MS	150
static int goodix_ts_power_ctrl(struct goodix_ts_core *cd, bool on)
{
	int ret = 0;

	if (on) {
		if (cd->avdd) {
			ret = regulator_enable(cd->avdd);
			if (ret < 0) {
				ts_err("Failed to enable avdd:%d", ret);
				goto power_off;
			}
			usleep_range(15000, 15100);
		}
		gpiod_set_value(cd->reset_gpiod, 1);
		usleep_range(4000, 4100);
		ret = brl_dev_confirm(cd);
		if (ret < 0)
			goto power_off;

		msleep(GOODIX_NORMAL_RESET_DELAY_MS);
		return 0;
	}

power_off:
	gpiod_set_value(cd->reset_gpiod, 0);
	if (cd->avdd)
		regulator_disable(cd->avdd);
	return ret;
}

/**
 * goodix_ts_power_on - Turn on power to the touch device
 * @core_data: pointer to touch core data
 * return: 0 ok, <0 failed
 */
int goodix_ts_power_on(struct goodix_ts_core *cd)
{
	int ret = 0;

	ts_info("Device power on");
	if (cd->power_on)
		return 0;

	ret = goodix_ts_power_ctrl(cd, true);
	if (!ret)
		cd->power_on = 1;
	else
		ts_err("failed power on, %d", ret);
	return ret;
}

/**
 * goodix_ts_power_off - Turn off power to the touch device
 * @core_data: pointer to touch core data
 * return: 0 ok, <0 failed
 */
int goodix_ts_power_off(struct goodix_ts_core *cd)
{
	int ret;

	ts_info("Device power off");
	if (!cd->power_on)
		return 0;

	goodix_ts_power_ctrl(cd, false);
	if (!ret)
		cd->power_on = 0;
	else
		ts_err("failed power off, %d", ret);

	return ret;
}

/* checksum_cmp: check data valid or not
 * @data: data need to be check
 * @size: data length need to be check(include the checksum bytes)
 * @mode: compare with U8 or U16 mode
 * */
int checksum_cmp(const u8 *data, int size, int mode)
{
	u32 cal_checksum = 0;
	u32 r_checksum = 0;
	u32 i;

	if (mode == CHECKSUM_MODE_U8_LE) {
		if (size < 2)
			return 1;
		for (i = 0; i < size - 2; i++)
			cal_checksum += data[i];
		r_checksum = data[size - 2] + (data[size - 1] << 8);
		return (cal_checksum & 0xFFFF) == r_checksum ? 0 : 1;
	}

	if (size < 4)
		return 1;
	for (i = 0; i < size - 4; i += 2)
		cal_checksum += data[i] + (data[i + 1] << 8);
	r_checksum = data[size - 4] + (data[size - 3] << 8) +
		(data[size - 2] << 16) + (data[size - 1] << 24);
	return cal_checksum == r_checksum ? 0 : 1;
}

#define FW_VERSION_INFO_ADDR		0x10014
static int goodix_ts_read_version(struct goodix_ts_core *cd,
			struct goodix_fw_version *version)
{
	int ret, i;
	u8 buf[sizeof(struct goodix_fw_version)] = {0};
	u8 temp_pid[8] = {0};

	for (i = 0; i < 2; i++) {
		ret = goodix_spi_read(cd, FW_VERSION_INFO_ADDR, buf, sizeof(buf));
		if (ret) {
			ts_info("read fw version: %d, retry %d", ret, i);
			ret = -GOODIX_EBUS;
			usleep_range(5000, 5100);
			continue;
		}

		if (!checksum_cmp(buf, sizeof(buf), CHECKSUM_MODE_U8_LE))
			break;

		ts_info("invalid fw version: checksum error!");
		ts_info("fw version:%*ph", (int)sizeof(buf), buf);
		ret = -GOODIX_ECHECKSUM;
		usleep_range(10000, 11000);
	}
	if (ret) {
		ts_err("failed get valied fw version");
		return ret;
	}
	memcpy(version, buf, sizeof(*version));
	memcpy(temp_pid, version->rom_pid, sizeof(version->rom_pid));
	ts_info("rom_pid:%s", temp_pid);
	ts_info("rom_vid:%*ph", (int)sizeof(version->rom_vid),
		version->rom_vid);
	ts_info("pid:%s", version->patch_pid);
	ts_info("vid:%*ph", (int)sizeof(version->patch_vid),
		version->patch_vid);
	ts_info("sensor_id:%d", version->sensor_id);

	return 0;
}

#define LE16_TO_CPU(x)  (x = le16_to_cpu(x))
#define LE32_TO_CPU(x)  (x = le32_to_cpu(x))
static int convert_ic_info(struct goodix_ic_info *info, const u8 *data)
{
	int i;
	struct goodix_ic_info_version *version = &info->version;
	struct goodix_ic_info_feature *feature = &info->feature;
	struct goodix_ic_info_param *parm = &info->parm;
	struct goodix_ic_info_misc *misc = &info->misc;

	info->length = le16_to_cpup((__le16 *)data);

	data += 2;
	memcpy(version, data, sizeof(*version));
	version->config_id = le32_to_cpu(version->config_id);

	data += sizeof(struct goodix_ic_info_version);
	memcpy(feature, data, sizeof(*feature));
	feature->freqhop_feature =
		le16_to_cpu(feature->freqhop_feature);
	feature->calibration_feature =
		le16_to_cpu(feature->calibration_feature);
	feature->gesture_feature =
		le16_to_cpu(feature->gesture_feature);
	feature->side_touch_feature =
		le16_to_cpu(feature->side_touch_feature);
	feature->stylus_feature =
		le16_to_cpu(feature->stylus_feature);

	data += sizeof(struct goodix_ic_info_feature);
	parm->drv_num = *(data++);
	parm->sen_num = *(data++);
	parm->button_num = *(data++);
	parm->force_num = *(data++);
	parm->active_scan_rate_num = *(data++);
	if (parm->active_scan_rate_num > MAX_SCAN_RATE_NUM) {
		ts_err("invalid scan rate num %d > %d",
			parm->active_scan_rate_num, MAX_SCAN_RATE_NUM);
		return -EINVAL;
	}
	for (i = 0; i < parm->active_scan_rate_num; i++)
		parm->active_scan_rate[i] =
			le16_to_cpup((__le16 *)(data + i * 2));

	data += parm->active_scan_rate_num * 2;
	parm->mutual_freq_num = *(data++);
	if (parm->mutual_freq_num > MAX_SCAN_FREQ_NUM) {
		ts_err("invalid mntual freq num %d > %d",
			parm->mutual_freq_num, MAX_SCAN_FREQ_NUM);
		return -EINVAL;
	}
	for (i = 0; i < parm->mutual_freq_num; i++)
		parm->mutual_freq[i] =
			le16_to_cpup((__le16 *)(data + i * 2));

	data += parm->mutual_freq_num * 2;
	parm->self_tx_freq_num = *(data++);
	if (parm->self_tx_freq_num > MAX_SCAN_FREQ_NUM) {
		ts_err("invalid tx freq num %d > %d",
			parm->self_tx_freq_num, MAX_SCAN_FREQ_NUM);
		return -EINVAL;
	}
	for (i = 0; i < parm->self_tx_freq_num; i++)
		parm->self_tx_freq[i] =
			le16_to_cpup((__le16 *)(data + i * 2));

	data += parm->self_tx_freq_num * 2;
	parm->self_rx_freq_num = *(data++);
	if (parm->self_rx_freq_num > MAX_SCAN_FREQ_NUM) {
		ts_err("invalid rx freq num %d > %d",
			parm->self_rx_freq_num, MAX_SCAN_FREQ_NUM);
		return -EINVAL;
	}
	for (i = 0; i < parm->self_rx_freq_num; i++)
		parm->self_rx_freq[i] =
			le16_to_cpup((__le16 *)(data + i * 2));

	data += parm->self_rx_freq_num * 2;
	parm->stylus_freq_num = *(data++);
	if (parm->stylus_freq_num > MAX_FREQ_NUM_STYLUS) {
		ts_err("invalid stylus freq num %d > %d",
			parm->stylus_freq_num, MAX_FREQ_NUM_STYLUS);
		return -EINVAL;
	}
	for (i = 0; i < parm->stylus_freq_num; i++)
		parm->stylus_freq[i] =
			le16_to_cpup((__le16 *)(data + i * 2));

	data += parm->stylus_freq_num * 2;
	memcpy(misc, data, sizeof(*misc));
	misc->cmd_addr = le32_to_cpu(misc->cmd_addr);
	misc->cmd_max_len = le16_to_cpu(misc->cmd_max_len);
	misc->cmd_reply_addr = le32_to_cpu(misc->cmd_reply_addr);
	misc->cmd_reply_len = le16_to_cpu(misc->cmd_reply_len);
	misc->fw_state_addr = le32_to_cpu(misc->fw_state_addr);
	misc->fw_state_len = le16_to_cpu(misc->fw_state_len);
	misc->fw_buffer_addr = le32_to_cpu(misc->fw_buffer_addr);
	misc->fw_buffer_max_len = le16_to_cpu(misc->fw_buffer_max_len);
	misc->frame_data_addr = le32_to_cpu(misc->frame_data_addr);
	misc->frame_data_head_len = le16_to_cpu(misc->frame_data_head_len);

	misc->fw_attr_len = le16_to_cpu(misc->fw_attr_len);
	misc->fw_log_len = le16_to_cpu(misc->fw_log_len);
	misc->stylus_struct_len = le16_to_cpu(misc->stylus_struct_len);
	misc->mutual_struct_len = le16_to_cpu(misc->mutual_struct_len);
	misc->self_struct_len = le16_to_cpu(misc->self_struct_len);
	misc->noise_struct_len = le16_to_cpu(misc->noise_struct_len);
	misc->touch_data_addr = le32_to_cpu(misc->touch_data_addr);
	misc->touch_data_head_len = le16_to_cpu(misc->touch_data_head_len);
	misc->point_struct_len = le16_to_cpu(misc->point_struct_len);
	LE32_TO_CPU(misc->mutual_rawdata_addr);
	LE32_TO_CPU(misc->mutual_diffdata_addr);
	LE32_TO_CPU(misc->mutual_refdata_addr);
	LE32_TO_CPU(misc->self_rawdata_addr);
	LE32_TO_CPU(misc->self_diffdata_addr);
	LE32_TO_CPU(misc->self_refdata_addr);
	LE32_TO_CPU(misc->iq_rawdata_addr);
	LE32_TO_CPU(misc->iq_refdata_addr);
	LE32_TO_CPU(misc->im_rawdata_addr);
	LE16_TO_CPU(misc->im_readata_len);
	LE32_TO_CPU(misc->noise_rawdata_addr);
	LE16_TO_CPU(misc->noise_rawdata_len);
	LE32_TO_CPU(misc->stylus_rawdata_addr);
	LE16_TO_CPU(misc->stylus_rawdata_len);
	LE32_TO_CPU(misc->noise_data_addr);
	LE32_TO_CPU(misc->esd_addr);

	return 0;
}

static void print_ic_info(struct goodix_ic_info *ic_info)
{
	struct goodix_ic_info_version *version = &ic_info->version;
	struct goodix_ic_info_feature *feature = &ic_info->feature;
	struct goodix_ic_info_param *parm = &ic_info->parm;
	struct goodix_ic_info_misc *misc = &ic_info->misc;

	ts_info("ic_info_length:                %d",
		ic_info->length);
	ts_info("info_customer_id:              0x%01X",
		version->info_customer_id);
	ts_info("info_version_id:               0x%01X",
		version->info_version_id);
	ts_info("ic_die_id:                     0x%01X",
		version->ic_die_id);
	ts_info("ic_version_id:                 0x%01X",
		version->ic_version_id);
	ts_info("config_id:                     0x%4X",
		version->config_id);
	ts_info("config_version:                0x%01X",
		version->config_version);
	ts_info("frame_data_customer_id:        0x%01X",
		version->frame_data_customer_id);
	ts_info("frame_data_version_id:         0x%01X",
		version->frame_data_version_id);
	ts_info("touch_data_customer_id:        0x%01X",
		version->touch_data_customer_id);
	ts_info("touch_data_version_id:         0x%01X",
		version->touch_data_version_id);

	ts_info("freqhop_feature:               0x%04X",
		feature->freqhop_feature);
	ts_info("calibration_feature:           0x%04X",
		feature->calibration_feature);
	ts_info("gesture_feature:               0x%04X",
		feature->gesture_feature);
	ts_info("side_touch_feature:            0x%04X",
		feature->side_touch_feature);
	ts_info("stylus_feature:                0x%04X",
		feature->stylus_feature);

	ts_info("Drv*Sen,Button,Force num:      %d x %d, %d, %d",
		parm->drv_num, parm->sen_num,
		parm->button_num, parm->force_num);

	ts_info("Cmd:                           0x%04X, %d",
		misc->cmd_addr, misc->cmd_max_len);
	ts_info("Cmd-Reply:                     0x%04X, %d",
		misc->cmd_reply_addr, misc->cmd_reply_len);
	ts_info("FW-State:                      0x%04X, %d",
		misc->fw_state_addr, misc->fw_state_len);
	ts_info("FW-Buffer:                     0x%04X, %d",
		misc->fw_buffer_addr, misc->fw_buffer_max_len);
	ts_info("Touch-Data:                    0x%04X, %d",
		misc->touch_data_addr, misc->touch_data_head_len);
	ts_info("point_struct_len:              %d",
		misc->point_struct_len);
	ts_info("mutual_rawdata_addr:           0x%04X",
		misc->mutual_rawdata_addr);
	ts_info("mutual_diffdata_addr:          0x%04X",
		misc->mutual_diffdata_addr);
	ts_info("self_rawdata_addr:             0x%04X",
		misc->self_rawdata_addr);
	ts_info("self_diffdata_addr:            0x%04X",
		misc->self_diffdata_addr);
	ts_info("stylus_rawdata_addr:           0x%04X, %d",
		misc->stylus_rawdata_addr, misc->stylus_rawdata_len);
	ts_info("esd_addr:                      0x%04X",
		misc->esd_addr);
}

/* return 1 if all data is zero or ff
 * else return 0
 */
int is_risk_data(const u8 *data, int size)
{
	int i;
	int zero_count =  0;
	int ff_count = 0;

	for (i = 0; i < size; i++) {
		if (data[i] == 0)
			zero_count++;
		else if (data[i] == 0xFF)
			ff_count++;
	}
	if (zero_count == size || ff_count == size) {
		ts_info("warning data is all %s\n",
			zero_count == size ? "0x00" : "0xFF");
		return 1;
	}

	return 0;
}

#define GOODIX_IC_INFO_ADDR		0x10070
#define GOODIX_IC_INFO_MAX_LEN		1024
static int goodix_ts_ic_info(struct goodix_ts_core *cd,
	struct goodix_ic_info *ic_info)
{
	int ret, i;
	u16 length = 0;
	u8 afe_data[GOODIX_IC_INFO_MAX_LEN] = {0};


	for (i = 0; i < GOODIX_RETRY_3; i++) {
		ret = goodix_spi_read(cd, GOODIX_IC_INFO_ADDR,
				   (u8 *)&length, sizeof(length));
		if (ret) {
			ts_info("failed get ic info length, %d", ret);
			usleep_range(5000, 5100);
			continue;
		}
		length = le16_to_cpu(length);
		if (length >= GOODIX_IC_INFO_MAX_LEN) {
			ts_info("invalid ic info length %d, retry %d",
				length, i);
			continue;
		}

		ret = goodix_spi_read(cd, GOODIX_IC_INFO_ADDR, afe_data, length);
		if (ret) {
			ts_info("failed get ic info data, %d", ret);
			usleep_range(5000, 5100);
			continue;
		}
		/* judge whether the data is valid */
		if (is_risk_data((const uint8_t *)afe_data, length)) {
			ts_info("fw info data invalid");
			usleep_range(5000, 5100);
			continue;
		}
		if (checksum_cmp((const uint8_t *)afe_data,
					length, CHECKSUM_MODE_U8_LE)) {
			ts_info("fw info checksum error!");
			usleep_range(5000, 5100);
			continue;
		}
		break;
	}
	if (i == GOODIX_RETRY_3) {
		ts_err("failed get ic info");
		return -EINVAL;
	}

	ret = convert_ic_info(ic_info, afe_data);
	if (ret) {
		ts_err("convert ic info encounter error");
		return ret;
	}

	print_ic_info(ic_info);

	/* check some key info */
	if (!ic_info->misc.cmd_addr || !ic_info->misc.fw_buffer_addr ||
	    !ic_info->misc.touch_data_addr) {
		ts_err("cmd_addr fw_buf_addr and touch_data_addr is null");
		return -EINVAL;
	}

	return 0;
}

static int goodix_spi_probe(struct spi_device *spi)
{
	int ret = 0;
	struct device *dev = &spi->dev;
	struct goodix_ts_core *cd;

	ts_info("goodix spi probe in %s", spi->modalias);
	ts_info("goodix spi probe in irq num %d, type %x", spi->irq, irq_get_trigger_type(spi->irq));

	/* init spi_device */
	spi->mode            = SPI_MODE_0;
	spi->bits_per_word   = 8;

	ts_info("spi_info: speed[%d] mode[%d] bits_per_word[%d]",
			spi->max_speed_hz, spi->mode, spi->bits_per_word);
	ret = spi_setup(spi);
	if (ret) {
		ts_err("failed set spi mode, %d", ret);
		return ret;
	}

	cd = devm_kzalloc(dev, sizeof(*cd), GFP_KERNEL);
	if (!cd)
		return -ENOMEM;

	spi_set_drvdata(spi, cd);
	cd->spi = spi;

	ret = goodix_ts_acpi_pdata(dev, cd);
	if (ret) {
		ts_err("no valid device info found from acpi, %d", ret);
		return -ENODEV;
	}

	ret = goodix_ts_power_on(cd);
	if (ret) {
		ts_err("failed power on");
		return ret;;
	}

	goodix_ts_read_version(cd, &cd->fw_version);
	goodix_ts_ic_info(cd, &cd->ic_info);
	if (gatp_hid_probe(cd))
		goto err_hid;

	ts_info("spi probe out");
	return 0;

err_hid:
	goodix_ts_power_off(cd);
	return -EFAULT;
}

static int goodix_spi_remove(struct spi_device *spi)
{
	struct goodix_ts_core *cd = spi_get_drvdata(spi);
	goodix_ts_power_off(cd);
	gatp_hid_remove(cd);
	return 0;
}

#ifdef CONFIG_ACPI
static const struct acpi_device_id brl_acpi_spi_match[] = {
	{ "GXTS7986", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, brl_acpi_spi_match);
#endif

static const struct spi_device_id spi_id_table[] = {
	{"gatp_hid", 0},
	{},
};

static struct spi_driver goodix_spi_driver = {
	.driver = {
		.name = "gatp_hid",
		#ifdef CONFIG_ACPI
		.acpi_match_table = ACPI_PTR(brl_acpi_spi_match),
		#endif
	},
	.id_table = spi_id_table,
	.probe = goodix_spi_probe,
	.remove = goodix_spi_remove,
};

module_spi_driver(goodix_spi_driver);
MODULE_DESCRIPTION("Goodix Touchscreen Module");
MODULE_AUTHOR("Goodix, Inc.");
MODULE_LICENSE("GPL v2");