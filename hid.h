#ifndef __GATP_HID_H__
#define __GATP_HID_H__
#include "main.h"

int gatp_hid_probe(struct goodix_ts_core *cd);
void gatp_hid_remove(struct goodix_ts_core *cd);

#endif