DIR="/home/bongb/bongbui321_gpt_dump_b"
./edl w gpt $DIR/gpt_main0.bin --memory=ufs --lun=0
./edl w gpt $DIR/gpt_main1.bin --memory=ufs --lun=1
./edl w gpt $DIR/gpt_main2.bin --memory=ufs --lun=2
./edl w gpt $DIR/gpt_main3.bin --memory=ufs --lun=3
./edl w gpt $DIR/gpt_main4.bin --memory=ufs --lun=4
./edl w gpt $DIR/gpt_main5.bin --memory=ufs --lun=5
./edl reset