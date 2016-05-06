init:
	pip install -r requirements.txt

test:
	python -m unittest discover

clean:
	find . -name '*.pyc' -exec rm -f {} +

.PHONY: test
