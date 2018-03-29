
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <fstream>
#include <map>

#include "DoubleEndedMemory.h"

using namespace std;

#define TAG_NORMAL 0xFF

static map<string, uint8_t> TagStrLookup;

bool LoadInputFile(TDoubleEndedMemory &Content, string Filename)
{
	ifstream File(Filename.c_str(), ifstream::in | ifstream::binary | ifstream::ate);
	if (File.bad()) {
		fprintf(stderr, "failed to read file: %s\n", Filename.c_str());
		return false;
	}

	size_t Length = File.tellg();
	File.seekg(0);

	Content.AppendStream(File, Length);
	Content.AppendU8(0);
	return true;
}

bool LoadMapFile(string Filename)
{
	FILE *fp = fopen(Filename.c_str(), "r");
	if (!fp) {
		fprintf(stderr, "failed to read file: %s\n", Filename.c_str());
		return false;
	}

	uint8_t Tag = 0;
	while (1) {
		char Line[256];
		if (!fgets(Line, sizeof(Line), fp)) {
			break;
		}

		char *Ptr = Line;
		string TagStr = "";
		while (1) {
			char c = *Ptr++;
			if (c < ' ') {
				break;
			}
			TagStr += c;
		}

		TagStrLookup.insert(pair<string, uint8_t>(TagStr, Tag++));
	}

	fclose(fp);
	return true;
}

bool WriteOutputFile(TDoubleEndedMemory &Content, string Filename)
{
	ofstream File(Filename.c_str(), ifstream::out | ifstream::binary);
	if (File.bad()) {
		fprintf(stderr, "failed to create file: %s\n", Filename.c_str());
		return false;
	}

	File.write((char *)Content.Begin, Content.Length());
	return true;
}

void WriteNormal(TDoubleEndedMemory &OutputData, char *Ptr, size_t Length)
{
	while (Length > 0) {
		size_t BlockLength = Length;
		if (BlockLength > 65535) {
			BlockLength = 65535;
		}

		OutputData.AppendU8(TAG_NORMAL);
		OutputData.AppendU16((uint16_t)BlockLength);
		OutputData.AppendMem(Ptr, BlockLength);

		Ptr += BlockLength;
		Length -= BlockLength;
	}
}

int Process(TDoubleEndedMemory &OutputData, char *&Input)
{
	char *Ptr = strstr(Input, "<!--");
	if (!Ptr) {
		size_t Length = strlen(Input);
		if (Length == 0) {
			return 0;
		}

		WriteNormal(OutputData, Input, Length);
		return 0;
	}

	if (Ptr != Input) {
		size_t Length = Ptr - Input;
		WriteNormal(OutputData, Input, Length);
		Input += Length;
	}

	char *End = strstr(Input, "-->");
	if (!End) {
		fprintf(stderr, "comment not terminated\n");
		return -1;
	}

	End += 3;

	string TagStr = "";
	while (Ptr < End) {
		TagStr += *Ptr++;
	}

	map<string, uint8_t>::iterator Iter = TagStrLookup.find(TagStr);
	if (Iter == TagStrLookup.end()) {
		fprintf(stderr, "WARNING: tag %s not known\n", TagStr.c_str());
	} else {
		OutputData.AppendU8(Iter->second);
	}

	Input = End;
	return 1;
}

int Help()
{
	printf("Usage:\n");
	printf("webserver_page_gen <input filename> <map file> <output filename>\n");
	return 1;
}

int main(int argc, char *argv[])
{
	argv++;
	argc--;

	while (argc != 3) {
		return Help();
	}

	string InputFilename = *argv++; argc--;
	string MapFilename = *argv++; argc--;
	string OutputFilename = *argv++; argc--;

	TDoubleEndedMemory InputData;
	if (!LoadInputFile(InputData, InputFilename)) {
		return 1;
	}

	if (!LoadMapFile(MapFilename)) {
		return 1;
	}

	TDoubleEndedMemory OutputData;
	OutputData.AppendMem("#!ssi\n", 6);

	char *Input = (char *)InputData.Begin;
	while (1) {
		int ret = Process(OutputData, Input);
		if (ret < 0) {
			return 1;
		}
		if (ret == 0) {
			break;
		}
	}

	if (!WriteOutputFile(OutputData, OutputFilename)) {
		return 1;
	}

	return 0;
}
