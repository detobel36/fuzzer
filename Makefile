all:
	@echo "Nothing here, please type: make help"

run:
	python3 fuzzer.py

clear: clean

clean:
	rm -f *.img
	rm -f deliverable.zip

deliverable: clear run
	rm success_Comment_Character_29952.img
	rm success_Color_Value_117.img
	zip deliverable.zip README.md *.img fuzzer.py

help:
	@echo "make command:"
	@echo "\thelp\t\tDisplay this help"
	@echo "\tclean\t\tRemove all images"
	@echo "\trun\t\tExecute fuzzer"
	@echo "\tdeliverable\tPrepare files to have deliverable"