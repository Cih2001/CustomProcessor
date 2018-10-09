# IDA processor module for challenge 10 of flare-on 2018

It is the implementation of an IDA Processor module for challenge 10 of [Flare-On 2018](http://flare-on.com/) for IDA Pro 7.

Inspired by a similar work by [Emanuele Cozzi](https://emanuelecozzi.net/posts/ctf/flareon-2018-challenge-12-subleq-rssb-writeup) This modules helps to speed up static analysis of presented VM using IDA.

VM specifications can be found [here](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/FlareOn5_Challenge10_Solution.pdf).


## Installation
    1. Copy `CustomProc.py` to the Ida 7 `proc` directory
    2. Copy `CustomProcInstructionSet` and its contents to the Ida 7 `proc` directory

## Usage
    1. Open sample codes from `Samples` in IDA 7 (using drag and drop.)
    3. Select 'CustomProcessor' from processor modules.

## Screen Shots
