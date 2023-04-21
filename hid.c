#include <linux/hid.h>
#include <uapi/linux/input.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/spi/spi.h>
#include <linux/delay.h>

#include "main.h"

#define GATP_HID_DESC_REG 		0x1058c
#define GATP_HID_REPORT_DESC_REG	0x105aa
#define GATP_HID_SIGN_REG 		0x10d30

/**
 * gatp_hid_parse() - hid-core .parse() callback
 * @hid:	hid device instance
 *
 * This function gets called during call to hid_add_device
 *
 * Return: 0 on success and non zero on error
 */
static int gatp_hid_parse(struct hid_device *hid)
{
	struct goodix_ts_core *cd = hid->driver_data;
	int ret;
	u16 rsize;
	uint8_t *rdesc;

	rsize = le16_to_cpu(cd->hid_desc.report_desc_lenght);
	if (!rsize || rsize > HID_MAX_DESCRIPTOR_SIZE) {
		ts_err("invalid report desc size %d", rsize);
		return -EINVAL;
	}

	rdesc = kzalloc(rsize, GFP_KERNEL);
	if (!rdesc)
		return -ENOMEM;

	ret = goodix_spi_read(cd, GATP_HID_REPORT_DESC_REG, rdesc, rsize);
	if (ret) {
		ts_err("failed get report desc");
		kfree(rdesc);
		return -EIO;
	}

	ret = hid_parse_report(hid, rdesc, rsize);
	if (ret) {
		ts_err("failed parse report");
		kfree(rdesc);
		return	ret;
	}
	kfree(rdesc);
	ts_info("rdesc parse success");
	return 0;
}

/* Empty callbacks with success return code */
static int gatp_hid_start(struct hid_device *hid)
{
	ts_info("hid start in");
	return 0;
}

static void gatp_hid_stop(struct hid_device *hid)
{
	ts_info("hid stop in");
}

static int gatp_hid_open(struct hid_device *hid)
{
	ts_info("hid open in");
	return 0;
}

static void gatp_hid_close(struct hid_device *hid)
{
	ts_info("hid stop in");
}

#define GATP_HID_RESET_CMD 	0x01
#define GATP_HID_GET_REPORT_CMD 0x02
#define GATP_HID_SET_REPORT_CMD 0x03
#define GATP_HID_SET_POWER_CMD  0x08

#define GATP_HID_MAX_INBUF_SIZE 128

#define GATP_HID_ACK_READY 	0x01

static int gatp_hid_check_ack_status(struct goodix_ts_core *cd)
{
	int ret, i;
	u8 buf[3] = {0};

	for (i = 0; i < 20; i++) {
		ret = goodix_spi_read(cd, cd->data_report_reg, buf, sizeof(buf));
		if (!ret && (buf[0] & GATP_HID_ACK_READY)) {
			return (buf[1] << 8) | buf[2];
		}
		ts_debug("ack data %*ph", 3, buf);
		usleep_range(10000, 11000);
	}
	return -EINVAL;
}

static int gatp_hid_get_raw_report(struct hid_device *hid, unsigned char reportnum,
			     __u8 *buf, size_t len, unsigned char report_type)
{
	struct goodix_ts_core *cd = hid->driver_data;
	int tx_len = 0, args_len = 0;
	u8 args[3];
	u8 tmp_buf[GATP_HID_MAX_INBUF_SIZE];
	int ret;

	if (report_type == HID_OUTPUT_REPORT)
		return -EINVAL;

	if (reportnum == 3) {
		/* get win8 signature */
		ret = goodix_spi_read(cd, GATP_HID_SIGN_REG + 2, buf, len);
		if (ret) {
			ts_err("failed get win8 sign:%d", ret);
			return -EINVAL;
		}
		return len;
	}

	if (reportnum >= 0x0F) {
		args[args_len++] = reportnum;
		reportnum = 0x0F;
	}
	args[args_len++] = cd->hid_desc.data_register & 0xFF;
	args[args_len++] = (cd->hid_desc.data_register >> 8) & 0xFF;

	/* clean goodix defiened 3 bytes header: Ack | len LSB| | len MSB */
	tmp_buf[tx_len++] = 0;
	tmp_buf[tx_len++] = 0;
	tmp_buf[tx_len++] = 0;
	tmp_buf[tx_len++] = cd->hid_desc.cmd_register & 0xFF;
	tmp_buf[tx_len++] = (cd->hid_desc.cmd_register >> 8) & 0xFF;

	tmp_buf[tx_len++] = ((report_type == HID_FEATURE_REPORT ? 0x03 : 0x01) << 4) | reportnum;
	tmp_buf[tx_len++] = GATP_HID_GET_REPORT_CMD;	


	memcpy(tmp_buf + tx_len, args, args_len);
	tx_len += args_len;

	ret = goodix_spi_write(cd, cd->data_report_reg, tmp_buf, tx_len);
	if (ret) {
		ts_err("failed send get feature cmd");
		return ret;
	}

	if (len > 0) {
		ret = gatp_hid_check_ack_status(cd);
		if (ret < 0) {
			ts_err("failed get ack ret %d", ret);
			return ret;
		}

		/* 3 represent goodix data header [ACK : data_len MSB : data_len LSB]
		 * 2 represent i2c-hid data_len LSB:data_len MSB */
		ret = goodix_spi_read(cd, cd->data_report_reg + 3 + 2, buf, len);
		if (ret) {
			ts_err("failed get feature data");
			return ret;
		}
	}
	return len;
}

static int gatp_hid_set_raw_report(struct hid_device *hid,unsigned char reportnum,
					 __u8 *buf, size_t len,
					unsigned char report_type)
{
	struct goodix_ts_core *cd = hid->driver_data;
	int tx_len = 0, args_len = 0;

	u8 args[8];
	u8 tmp_buf[GATP_HID_MAX_INBUF_SIZE];
	int ret;

	if (reportnum >= 0x0F) {
		args[args_len++] = reportnum;
		reportnum = 0x0F;
	}

	args[args_len++] = cd->hid_desc.data_register & 0xFF;
	args[args_len++] = (cd->hid_desc.data_register >> 8) & 0xFF;

	args[args_len++] = (2 + len) & 0xFF;
	args[args_len++] = ((2 + len) >> 8) & 0xFF;

	/* clean goodix defiened 3 bytes header: Ack | len LSB| | len MSB */
	tmp_buf[tx_len++] = 0;
	tmp_buf[tx_len++] = 0;
	tmp_buf[tx_len++] = 0;
	tmp_buf[tx_len++] = cd->hid_desc.cmd_register & 0xFF;
	tmp_buf[tx_len++] = (cd->hid_desc.cmd_register >> 8) & 0xFF;

	tmp_buf[tx_len++] = ((report_type == HID_FEATURE_REPORT ? 0x03 : 0x02) << 4) | reportnum;
	tmp_buf[tx_len++] = GATP_HID_SET_REPORT_CMD;	

	memcpy(tmp_buf + tx_len, args, args_len);
	tx_len += args_len;

	memcpy(tmp_buf + tx_len, buf, len);
	tx_len += len;

	ret = goodix_spi_write(cd, cd->data_report_reg, tmp_buf, tx_len);
	if (ret) {
		ts_err("failed send report %*ph", tx_len, tmp_buf);
		return ret;
	}
	return len;
}

static int gatp_raw_request(struct hid_device *hid, unsigned char reportnum,
			     __u8 *buf, size_t len, unsigned char rtype,
			     int reqtype)
{
	ts_debug("report num %d, len %lu, rtype %d, reqtype %d", reportnum, len, rtype, reqtype);
	switch (reqtype) {
	case HID_REQ_GET_REPORT:
		return gatp_hid_get_raw_report(hid, reportnum, buf, len, rtype);
	case HID_REQ_SET_REPORT:
		if (buf[0] != reportnum)
			return -EINVAL;
		return gatp_hid_set_raw_report(hid, reportnum, buf, len, rtype);
	default:
		return -EIO;
	}

	return -EINVAL;
}

static struct hid_ll_driver gatp_hid_ll_driver = {
	.parse = gatp_hid_parse,
	.start = gatp_hid_start,
	.stop = gatp_hid_stop,
	.open = gatp_hid_open,
	.close = gatp_hid_close,
	.raw_request = gatp_raw_request
};

#define GATP_HID_HEADER_LEN	3
#define GATP_HID_COOR_LEN	84
#define GATP_HID_DIFF_LEN	(4083 + 12)
#define GATP_HID_MAX_INPUT_LEN  (GATP_HID_HEADER_LEN + GATP_HID_COOR_LEN + GATP_HID_DIFF_LEN)

static irqreturn_t gatp_hid_irq(int irq, void *data)
{
	struct goodix_ts_core *cd = data;
	int diff_data_len = 0;
	int ret;

	ret = goodix_spi_read(cd, cd->data_report_reg, cd->rawbuf, GATP_HID_MAX_INPUT_LEN);
	if (ret) {
		ts_err("failed get input data");
		goto err_out;
	}

	/* send coor data */
	if( ( cd->rawbuf[GATP_HID_HEADER_LEN] + (cd->rawbuf[GATP_HID_HEADER_LEN + 1] << 8) ) != 
	    GATP_HID_COOR_LEN  ){
		ts_err("coor data len is invalid:%d,need:%d",
			( cd->rawbuf[GATP_HID_HEADER_LEN] + (cd->rawbuf[GATP_HID_HEADER_LEN + 1] << 8 )),
			GATP_HID_COOR_LEN);
		goto err_out;
	}
	hid_input_report(cd->hid, HID_INPUT_REPORT, cd->rawbuf+GATP_HID_HEADER_LEN + 2, GATP_HID_COOR_LEN -2 , 1);

	diff_data_len = cd->rawbuf[GATP_HID_HEADER_LEN + GATP_HID_COOR_LEN] + 
			(cd->rawbuf[GATP_HID_HEADER_LEN + GATP_HID_COOR_LEN + 1] << 8);

	/* send diff data */
	hid_input_report(cd->hid, HID_INPUT_REPORT, cd->rawbuf+GATP_HID_HEADER_LEN + GATP_HID_COOR_LEN +2, diff_data_len -2, 1);

err_out:
	return IRQ_HANDLED;
}

static int gatp_hid_irq_init(struct goodix_ts_core *cd)
{
	unsigned long irqflags = 0;
	int ret;

	if (!irq_get_trigger_type(cd->spi->irq))
		irqflags = IRQF_TRIGGER_FALLING;

	ret = devm_request_threaded_irq(&cd->spi->dev, cd->spi->irq,
					NULL, gatp_hid_irq,
				   	irqflags | IRQF_ONESHOT, "gatp_hid", cd);
	if (ret < 0) {
		ts_err("Could not register for %s interrupt, irq = %d,"
			" ret = %d\n", "gatp_hid", cd->spi->irq, ret);
		return ret;
	}
	return ret;
}

static int gatp_hid_desc_fetch(struct goodix_ts_core *cd)
{
	int ret;

	ret = goodix_spi_read(cd, GATP_HID_DESC_REG, cd->desc_buffer, sizeof(struct gatp_hid_desc));
	if (ret) {
		ts_err("failed get hid desc");
		return ret;
	}

	ts_info("desc_length:           %d", cd->hid_desc.desc_length);
	ts_info("bcd_version:           0x%x", cd->hid_desc.bcd_version);
	ts_info("report_desc_lenght:    %d", cd->hid_desc.report_desc_lenght);
	ts_info("report_desc_register:  0x%x", cd->hid_desc.report_desc_register);
	ts_info("input_register:        0x%x", cd->hid_desc.input_register);
	ts_info("max_input_length:      %d", cd->hid_desc.max_input_length);
	ts_info("output_register:       0x%x", cd->hid_desc.output_register);
	ts_info("max_output_length:     %d", cd->hid_desc.max_output_length);
	ts_info("cmd_register:          0x%x", cd->hid_desc.cmd_register);
	ts_info("data_register:         0x%x", cd->hid_desc.data_register);
	ts_info("vendor_id:             0x%x", cd->hid_desc.vendor_id);
	ts_info("product_id:            0x%x", cd->hid_desc.product_id);
	ts_info("version_id:            0x%x", cd->hid_desc.version_id);

	return 0;
}

/**
 * gatp_hid_probe() - hid register ll driver
 * @cd:	Client data pointer
 *
 * This function is used to allocate and add HID device.
 *
 * Return: 0 on success, non zero on error
 */
int gatp_hid_probe(struct goodix_ts_core *cd)
{
	int ret;
	struct hid_device *hid;

	ret = gatp_hid_irq_init(cd);
	if (ret) {
		ts_err("failed init irq");
		return ret;
	}

	ret = gatp_hid_desc_fetch(cd);
	if (ret) {
		ts_err("failed get hid desc");
		return ret;
	}

	hid = hid_allocate_device();
	if (IS_ERR(hid)) {
		ret = PTR_ERR(hid);
		return	-ENOMEM;
	}

	hid->driver_data = cd;
	hid->ll_driver = &gatp_hid_ll_driver;
	hid->bus = BUS_SPI;
	hid->dev.parent = &cd->spi->dev;

	hid->version = le16_to_cpu(cd->hid_desc.bcd_version);
	hid->vendor = le16_to_cpu(cd->hid_desc.vendor_id);
	hid->product = le16_to_cpu(cd->hid_desc.product_id);
	snprintf(hid->name, sizeof(hid->name), "%s %04X:%04X", "hid-gatp",
		hid->vendor, hid->product);

	ret = hid_add_device(hid);
	if (ret) {
		ts_err("failed add hid device");
		goto err_hid_data;
	}
	ts_info("hid init success");
	cd->hid = hid;
	return 0;

err_hid_data:
	hid_destroy_device(hid);
	return ret;
}

/**
 * gatp_hid_remove() - Remove registered hid device
 * @cd:	client data pointer
 *
 * This function is used to destroy allocatd HID device.
 */
void gatp_hid_remove(struct goodix_ts_core *cd)
{
	hid_destroy_device(cd->hid);
}
