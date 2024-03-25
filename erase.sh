FLASH_SLOT="b"
./edl e aop_$FLASH_SLOT --memory=ufs
./edl e devcfg_$FLASH_SLOT --memory=ufs
./edl e xbl_$FLASH_SLOT --memory=ufs
./edl e xbl_config_$FLASH_SLOT --memory=ufs
./edl e abl_$FLASH_SLOT --memory=ufs
./edl e boot_$FLASH_SLOT --memory=ufs
./edl e system_$FLASH_SLOT --memory=ufs
./edl reset