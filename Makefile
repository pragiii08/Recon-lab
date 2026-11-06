.PHONY: test lab scan demo
test:
	python3 -m unittest discover -s tests -v
lab:
	python3 -m lab.target_server
scan:
	python3 -m reconlab full 127.0.0.1
demo:
	./scripts/run_lab.sh
