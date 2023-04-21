#ifndef __GOODIX_MAIN_H__
#define __GOODIX_MAIN_H__
#include <linux/hid.h>
#include <linux/sizes.h>

#define GOODIX_DRIVER_VERSION			"v1.0.1"
#define AVDD_LDO_CTRL_ENABLE 0

#define GOODIX_RETRY_3					3

enum CHECKSUM_MODE {
	CHECKSUM_MODE_U8_LE,
	CHECKSUM_MODE_U16_LE,
};

enum GOODIX_ERR_CODE {
	GOODIX_EBUS      = (1<<0),
	GOODIX_ECHECKSUM = (1<<1),
	GOODIX_EVERSION  = (1<<2),
	GOODIX_ETIMEOUT  = (1<<3),
	GOODIX_EMEMCMP   = (1<<4),

	GOODIX_EOTHER    = (1<<7)
};

/* log macro */
extern bool debug_log_flag;
#define ts_info(fmt, arg...) \
		pr_info("[GATP-INF][%s] "fmt"\n", __func__, ##arg)
#define	ts_err(fmt, arg...) \
		pr_err("[GATP-ERR][%s] "fmt"\n", __func__, ##arg)
#define ts_debug(fmt, arg...) \
		{if (debug_log_flag) \
		pr_info("[GATP-DBG][%s] "fmt"\n", __func__, ##arg);}


#define MAX_SCAN_FREQ_NUM            8
#define MAX_SCAN_RATE_NUM            8
#define MAX_FREQ_NUM_STYLUS          8
#define MAX_STYLUS_SCAN_FREQ_NUM     6
#pragma pack(1)

struct goodix_fw_version {
	u8 rom_pid[6];               /* rom PID */
	u8 rom_vid[3];               /* Mask VID */
	u8 rom_vid_reserved;
	u8 patch_pid[8];              /* Patch PID */
	u8 patch_vid[4];              /* Patch VID */
	u8 patch_vid_reserved;
	u8 sensor_id;
	u8 reserved[2];
	u16 checksum;
};

struct goodix_ic_info_version {
	u8 info_customer_id;
	u8 info_version_id;
	u8 ic_die_id;
	u8 ic_version_id;
	u32 config_id;
	u8 config_version;
	u8 frame_data_customer_id;
	u8 frame_data_version_id;
	u8 touch_data_customer_id;
	u8 touch_data_version_id;
	u8 reserved[3];
};

struct goodix_ic_info_feature { /* feature info*/
	u16 freqhop_feature;
	u16 calibration_feature;
	u16 gesture_feature;
	u16 side_touch_feature;
	u16 stylus_feature;
};

struct goodix_ic_info_param { /* param */
	u8 drv_num;
	u8 sen_num;
	u8 button_num;
	u8 force_num;
	u8 active_scan_rate_num;
	u16 active_scan_rate[MAX_SCAN_RATE_NUM];
	u8 mutual_freq_num;
	u16 mutual_freq[MAX_SCAN_FREQ_NUM];
	u8 self_tx_freq_num;
	u16 self_tx_freq[MAX_SCAN_FREQ_NUM];
	u8 self_rx_freq_num;
	u16 self_rx_freq[MAX_SCAN_FREQ_NUM];
	u8 stylus_freq_num;
	u16 stylus_freq[MAX_FREQ_NUM_STYLUS];
};

struct goodix_ic_info_misc { /* other data */
	u32 cmd_addr;
	u16 cmd_max_len;
	u32 cmd_reply_addr;
	u16 cmd_reply_len;
	u32 fw_state_addr;
	u16 fw_state_len;
	u32 fw_buffer_addr;
	u16 fw_buffer_max_len;
	u32 frame_data_addr;
	u16 frame_data_head_len;
	u16 fw_attr_len;
	u16 fw_log_len;
	u8 pack_max_num;
	u8 pack_compress_version;
	u16 stylus_struct_len;
	u16 mutual_struct_len;
	u16 self_struct_len;
	u16 noise_struct_len;
	u32 touch_data_addr;
	u16 touch_data_head_len;
	u16 point_struct_len;
	u16 reserved1;
	u16 reserved2;
	u32 mutual_rawdata_addr;
	u32 mutual_diffdata_addr;
	u32 mutual_refdata_addr;
	u32 self_rawdata_addr;
	u32 self_diffdata_addr;
	u32 self_refdata_addr;
	u32 iq_rawdata_addr;
	u32 iq_refdata_addr;
	u32 im_rawdata_addr;
	u16 im_readata_len;
	u32 noise_rawdata_addr;
	u16 noise_rawdata_len;
	u32 stylus_rawdata_addr;
	u16 stylus_rawdata_len;
	u32 noise_data_addr;
	u32 esd_addr;
};

struct goodix_ic_info {
	u16 length;
	struct goodix_ic_info_version version;
	struct goodix_ic_info_feature feature;
	struct goodix_ic_info_param parm;
	struct goodix_ic_info_misc misc;
};
#pragma pack()

struct gatp_hid_desc {
	u16 desc_length;
	u16 bcd_version;
	u16 report_desc_lenght;
	u16 report_desc_register;
	u16 input_register;
	u16 max_input_length;
	u16 output_register;
	u16 max_output_length;
	u16 cmd_register;
	u16 data_register;
	u16 vendor_id;
	u16 product_id;
	u16 version_id;
	u32 reserved;
} __packed;

struct goodix_ts_core {
	struct spi_device *spi;
	struct hid_device *hid;
	struct goodix_fw_version fw_version;
	struct goodix_ic_info ic_info;
	struct regulator *avdd;

	u32 data_report_reg;

	union {
		u8 desc_buffer[sizeof(struct gatp_hid_desc)];
		struct gatp_hid_desc hid_desc;
	};

	int power_on;
	struct gpio_desc *reset_gpiod;
	struct gpio_desc *irq_gpiod;

	atomic_t irq_enabled;
	atomic_t suspended;

	u8 rawbuf[SZ_8K];
};

int goodix_spi_read(struct goodix_ts_core *cd, unsigned int addr,
	unsigned char *data, unsigned int len);
int goodix_spi_write(struct goodix_ts_core *cd, unsigned int addr,
		unsigned char *data, unsigned int len);
#endif
