.PHONY:  all setup_dmng setup_test landlock_service graphs

INPUT    := input.mpc

# some versions have a different name, switch if needed
# CONVERT := convert
CONVERT := convert

FFMPEG = ffmpeg -y -loglevel quiet

# POLICY_CONVERT := ./convert_landlock_ubuntu.json
POLICY_CONVERT := ./convert_landlock.json
# POLICY_FFMPEG := ./ffmpeg_landlock_ubuntu.json
POLICY_FFMPEG := ./ffmpeg_landlock.json

TEST          = ./target/release/dmng-test
LANDLOCK_TEST = $(TEST) --type landlock
EBPF_TEST     = $(TEST) --type ebpf

graphs:
	@ cd graphs && python main.py

setup_test:
	@ echo "[*] Setting up images"
	@ convert -size 32x32 xc:gray +noise gaussian img32x32.png
	@ convert -size 640x480 xc:gray +noise gaussian img640x480.png
	@ convert -size 1920x1080 xc:gray +noise gaussian img1920x1080.png

	@ # echo "[*] Creating 10x video"
	@ # $(FFMPEG) -stream_loop 10 -i input.mp4 input2.mp4
	@ # echo "[*] Creating 100x video"
	@ # $(FFMPEG) -stream_loop 100 -i input.mp4 input3.mp4

setup_dmng:
	@ # backup the folder if you don't want it gone forever
	@ rm -rf ~/.config/dmng
	@ dmng -c "$(CONVERT) img32x32.png output.mpc" --setcontext convert > /dev/null
	@ dmng -c "$(CONVERT) img640x480.png output.mpc" -t static > /dev/null
	@ dmng -c "$(CONVERT) img1920x1080.png output.mpc" -t ptrace --simulate 100 > /dev/null

	@ dmng -c "$(FFMPEG) -i input.mp4 -codec copy output.mp4" --setcontext ffmpeg > /dev/null
	@ dmng -c "$(FFMPEG) -i input.mp4 -codec copy output.mp4" -t static > /dev/null
	@ dmng -c "$(FFMPEG) -i input.mp4 -codec copy output.mp4" -t ptrace --simulate 100 > /dev/null


build:
	@ cargo build --release
	@ cd landlock_service && cargo build --release

none-convert-small:
	@ $(TEST) --type none --name convert_id --command "$(CONVERT) img32x32.png output.mpc"
	@ $(TEST) --type none --name convert_enhance --command "$(CONVERT) img32x32.png -enhance output.mpc"
	@ $(TEST) --type none --name convert_resize --command "$(CONVERT) img32x32.png -resize 50% output.mpc"
	@ $(TEST) --type none --name convert_sharpen --command "$(CONVERT) img32x32.png -sharpen 0x2.0 output.mpc"
	@ $(TEST) --type none --name convert_rotate --command "$(CONVERT) img32x32.png -rotate 90 output.mpc"
	@ $(TEST) --type none --name convert_swirl --command "$(CONVERT) img32x32.png -swirl 90 output.mpc"

none-convert-med:
	@ $(TEST) --type none --name convert_id --command "$(CONVERT) img640x480.png output.mpc"
	@ $(TEST) --type none --name convert_enhance --command "$(CONVERT) img640x480.png -enhance output.mpc"
	@ $(TEST) --type none --name convert_resize --command "$(CONVERT) img640x480.png -resize 50% output.mpc"
	@ $(TEST) --type none --name convert_sharpen --command "$(CONVERT) img640x480.png -sharpen 0x2.0 output.mpc"
	@ $(TEST) --type none --name convert_rotate --command "$(CONVERT) img640x480.png -rotate 90 output.mpc"
	@ $(TEST) --type none --name convert_swirl --command "$(CONVERT) img640x480.png -swirl 90 output.mpc"

none-convert-large:
	@ $(TEST) --type none --name convert_id --command "$(CONVERT) img1920x1080.png output.mpc"
	@ $(TEST) --type none --name convert_enhance --command "$(CONVERT) img1920x1080.png -enhance output.mpc"
	@ $(TEST) --type none --name convert_resize --command "$(CONVERT) img1920x1080.png -resize 50% output.mpc"
	@ $(TEST) --type none --name convert_sharpen --command "$(CONVERT) img1920x1080.png -sharpen 0x2.0 output.mpc"
	@ $(TEST) --type none --name convert_rotate --command "$(CONVERT) img1920x1080.png -rotate 90 output.mpc"
	@ $(TEST) --type none --name convert_swirl --command "$(CONVERT) img1920x1080.png -swirl 90 output.mpc"

none-ffmpeg-a:
	@ $(TEST) --type none --name ffmpeg_decode --command "$(FFMPEG) -i input.mp4 -f null"
	@ $(TEST) --type none --name ffmpeg_copy --command "$(FFMPEG) -i input.mp4 -codec copy output.mp4"
	@ $(TEST) --type none --name ffmpeg_cut --command "$(FFMPEG) -i input.mp4 -vcodec copy -acodec copy -ss 00:00:00 -t 00:30:00 output.mp4"
	@ $(TEST) --type none --name ffmpeg_loop --command "$(FFMPEG) -stream_loop 3 -i input.mp4 -c copy output.mp4"
	@ $(TEST) --type none --name ffmpeg_extract_audio --command "$(FFMPEG) -i input.mp4 output.mp3"

none-ffmpeg-b:
	@ $(TEST) --type none --name ffmpeg_decode --command "$(FFMPEG) -i input2.mp4 -f null"
	@ $(TEST) --type none --name ffmpeg_copy --command "$(FFMPEG) -i input2.mp4 -codec copy output.mp4"
	@ $(TEST) --type none --name ffmpeg_cut --command "$(FFMPEG) -i input2.mp4 -vcodec copy -acodec copy -ss 00:00:00 -t 00:30:00 output.mp4"
	@ $(TEST) --type none --name ffmpeg_loop --command "$(FFMPEG) -stream_loop 3 -i input2.mp4 -c copy output.mp4"
	@ $(TEST) --type none --name ffmpeg_extract_audio --command "$(FFMPEG) -i input2.mp4 output.mp3"

none-ffmpeg-c:
	@ $(TEST) --type none --name ffmpeg_decode --command "$(FFMPEG) -i input3.mp4 -f null"
	@ $(TEST) --type none --name ffmpeg_copy --command "$(FFMPEG) -i input3.mp4 -codec copy output.mp4"
	@ $(TEST) --type none --name ffmpeg_cut --command "$(FFMPEG) -i input3.mp4 -vcodec copy -acodec copy -ss 00:00:00 -t 00:30:00 output.mp4"
	@ $(TEST) --type none --name ffmpeg_loop --command "$(FFMPEG) -stream_loop 3 -i input3.mp4 -c copy output.mp4"
	@ $(TEST) --type none --name ffmpeg_extract_audio --command "$(FFMPEG) -i input3.mp4 output.mp3"


landlock-convert-small:
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_id --command "$(CONVERT) img32x32.png output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_enhance --command "$(CONVERT) img32x32.png -enhance output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_resize --command "$(CONVERT) img32x32.png -resize 50% output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_sharpen --command "$(CONVERT) img32x32.png -sharpen 0x2.0 output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_rotate --command "$(CONVERT) img32x32.png -rotate 90 output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_swirl --command "$(CONVERT) img32x32.png -swirl 90 output.mpc"

landlock-convert-med:
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_id --command "$(CONVERT) img640x480.png output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_enhance --command "$(CONVERT) img640x480.png -enhance output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_resize --command "$(CONVERT) img640x480.png -resize 50% output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_sharpen --command "$(CONVERT) img640x480.png -sharpen 0x2.0 output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_rotate --command "$(CONVERT) img640x480.png -rotate 90 output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_swirl --command "$(CONVERT) img640x480.png -swirl 90 output.mpc"

landlock-convert-large:
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_id --command "$(CONVERT) img1920x1080.png output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_enhance --command "$(CONVERT) img1920x1080.png -enhance output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_resize --command "$(CONVERT) img1920x1080.png -resize 50% output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_sharpen --command "$(CONVERT) img1920x1080.png -sharpen 0x2.0 output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_rotate --command "$(CONVERT) img1920x1080.png -rotate 90 output.mpc"
	@ $(LANDLOCK_TEST) --policy $(POLICY_CONVERT) --name convert_swirl --command "$(CONVERT) img1920x1080.png -swirl 90 output.mpc"


landlock-ffmpeg-a:
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_decode --command "$(FFMPEG) -i input.mp4 -f null"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_copy --command "$(FFMPEG) -i input.mp4 -codec copy output.mp4"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_cut --command "$(FFMPEG) -i input.mp4 -vcodec copy -acodec copy -ss 00:00:00 -t 00:30:00 output.mp4"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_loop --command "$(FFMPEG) -stream_loop 3 -i input.mp4 -c copy output.mp4"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_extract_audio --command "$(FFMPEG) -i input.mp4 output.mp3"

landlock-ffmpeg-b:
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_decode --command "$(FFMPEG) -i input2.mp4 -f null"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_copy --command "$(FFMPEG) -i input2.mp4 -codec copy output.mp4"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_cut --command "$(FFMPEG) -i input2.mp4 -vcodec copy -acodec copy -ss 00:00:00 -t 00:30:00 output.mp4"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_loop --command "$(FFMPEG) -stream_loop 3 -i input2.mp4 -c copy output.mp4"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_extract_audio --command "$(FFMPEG) -i input2.mp4 output.mp3"

landlock-ffmpeg-c:
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_decode --command "$(FFMPEG) -i input3.mp4 -f null"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_copy --command "$(FFMPEG) -i input3.mp4 -codec copy output.mp4"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_cut --command "$(FFMPEG) -i input3.mp4 -vcodec copy -acodec copy -ss 00:00:00 -t 00:30:00 output.mp4"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_loop --command "$(FFMPEG) -stream_loop 3 -i input3.mp4 -c copy output.mp4"
	@ $(LANDLOCK_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_extract_audio --command "$(FFMPEG) -i input3.mp4 output.mp3"

ebpf-convert-small:
	@ touch tmp
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_id --command "$(CONVERT) img32x32.png output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_enhance --command "$(CONVERT) img32x32.png -enhance output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_resize --command "$(CONVERT) img32x32.png -resize 50% output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_sharpen --command "$(CONVERT) img32x32.png -sharpen 0x2.0 output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_rotate --command "$(CONVERT) img32x32.png -rotate 90 output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_swirl --command "$(CONVERT) img32x32.png -swirl 90 output.mpc" 
	@ rm tmp

ebpf-convert-med:
	@ touch tmp
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_id --command "$(CONVERT) img640x480.png output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_enhance --command "$(CONVERT) img640x480.png -enhance output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_resize --command "$(CONVERT) img640x480.png -resize 50% output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_sharpen --command "$(CONVERT) img640x480.png -sharpen 0x2.0 output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_rotate --command "$(CONVERT) img640x480.png -rotate 90 output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_swirl --command "$(CONVERT) img640x480.png -swirl 90 output.mpc" 
	@ rm tmp

ebpf-convert-large:
	@ touch tmp
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_id --command "$(CONVERT) img1920x1080.png output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_enhance --command "$(CONVERT) img1920x1080.png -enhance output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_resize --command "$(CONVERT) img1920x1080.png -resize 50% output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_sharpen --command "$(CONVERT) img1920x1080.png -sharpen 0x2.0 output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_rotate --command "$(CONVERT) img1920x1080.png -rotate 90 output.mpc" 
	@ $(EBPF_TEST) --policy $(POLICY_CONVERT) --name convert_swirl --command "$(CONVERT) img1920x1080.png -swirl 90 output.mpc" 
	@ rm tmp

ebpf-ffmpeg-a:
	@ touch tmp
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_decode --command "$(FFMPEG) -i input.mp4 -f null" 
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_copy --command "$(FFMPEG) -i input.mp4 -codec copy output.mp4" 
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_cut --command "$(FFMPEG) -i input.mp4 -vcodec copy -acodec copy -ss 00:00:00 -t 00:30:00 output.mp4" 
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_loop --command "$(FFMPEG) -stream_loop 3 -i input.mp4 -c copy output.mp4" 
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_extract_audio --command "$(FFMPEG) -i input.mp4 output.mp3" 

ebpf-ffmpeg-b:
	@ touch tmp
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_decode --command "$(FFMPEG) -i input2.mp4 -f null"
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_copy --command "$(FFMPEG) -i input2.mp4 -codec copy output.mp4"
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_cut --command "$(FFMPEG) -i input2.mp4 -vcodec copy -acodec copy -ss 00:00:00 -t 00:30:00 output.mp4"
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_loop --command "$(FFMPEG) -stream_loop 3 -i input2.mp4 -c copy output.mp4"
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_extract_audio --command "$(FFMPEG) -i input2.mp4 output.mp3"

ebpf-ffmpeg-c:
	@ touch tmp
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_decode --command "$(FFMPEG) -i input3.mp4 -f null"
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_copy --command "$(FFMPEG) -i input3.mp4 -codec copy output.mp4"
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_cut --command "$(FFMPEG) -i input3.mp4 -vcodec copy -acodec copy -ss 00:00:00 -t 00:30:00 output.mp4"
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_loop --command "$(FFMPEG) -stream_loop 3 -i input3.mp4 -c copy output.mp4"
	@ $(EBPF_TEST) --policy $(POLICY_FFMPEG) --name ffmpeg_extract_audio --command "$(FFMPEG) -i input3.mp4 output.mp3"
	@ rm tmp

clean:
	@ rm $(INPUT) $(IMG)-1.zip $(IMG)-1.zip.1 *.cache