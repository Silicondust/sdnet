
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fstream>
#include <map>

#include "DoubleEndedMemory.h"

using namespace std;

bool LoadFile(TDoubleEndedMemory &Content, string Filename)
{
	ifstream File(Filename.c_str());
	if (!File || File.bad()) {
		fprintf(stderr, "failed to read file: %s\n", Filename.c_str());
		return false;
	}

	File.seekg(0, std::ios::end);
	size_t Length = File.tellg();
	File.seekg(0);

	Content.AppendStream(File, Length);
	return true;
}

bool WriteFile(TDoubleEndedMemory &Content, string Filename)
{
	ofstream File(Filename.c_str());
	if (!File || File.bad()) {
		fprintf(stderr, "failed to create file: %s\n", Filename.c_str());
		return false;
	}

	File.write((char *)Content.Begin, Content.Length());
	return true;
}

int Help()
{
	printf("Usage:\n");
	printf("rom_gen blank <size> <rom filename>\n");
	printf("rom_gen add-raw <offset> <max length> <input filename> <rom filename>\n");
	printf("rom_gen checksum <fill-to size> <rom filename>\n");
	return 1;
}

int main_blank(int argc, char *argv[])
{
	if (argc < 2) {
		return Help();
	}

	uint32_t Size = strtoul(*argv++, NULL, 0); argc--;
	string RomFilename = *argv++; argc--;

	TDoubleEndedMemory RomData;
	RomData.AppendFill(0xFF, Size);

	if (!WriteFile(RomData, RomFilename)) {
		return 1;
	}

	return 0;
}

int main_add_raw(int argc, char *argv[])
{
	if (argc < 4) {
		return Help();
	}

	uint32_t Offset = strtoul(*argv++, NULL, 0); argc--;
	uint32_t MaxLength = strtoul(*argv++, NULL, 0); argc--;
	string InputFilename = *argv++; argc--;
	string RomFilename = *argv++; argc--;

	TDoubleEndedMemory RomData;
	if (!LoadFile(RomData, RomFilename)) {
		return 1;
	}

	TDoubleEndedMemory InputData;
	if (!LoadFile(InputData, InputFilename)) {
		return 1;
	}

	if (InputData.Length() > MaxLength) {
		fprintf(stderr, "section data larger than section: %s\n", InputFilename.c_str());
		return 1;
	}

	if (Offset + InputData.Length() > RomData.Length()) {
		RomData.AppendFill(0xFF, Offset + InputData.Length() - RomData.Length());
	}

	memcpy(RomData.Begin + Offset, InputData.Begin, InputData.Length());

	if (!WriteFile(RomData, RomFilename)) {
		return 1;
	}

	return 0;
}

int main_checksum(int argc, char *argv[])
{
	if (argc < 2) {
		return Help();
	}

	size_t FillToSize = strtoul(*argv++, NULL, 0); argc--;
	string RomFilename = *argv++; argc--;

	TDoubleEndedMemory RomData;
	if (!LoadFile(RomData, RomFilename)) {
		return 1;
	}

	uint8_t *Ptr = RomData.Begin;
	uint8_t *End = RomData.End;
	uint32_t Checksum = 0;

	while (Ptr < End) {
		Checksum += (uint32_t)(*Ptr++);
	}

	size_t DataLength =  RomData.Length();
	if (FillToSize > DataLength) {
		Checksum += 0xFFUL * (FillToSize - DataLength);
	}

	printf("checksum = %08X\n", (unsigned int)Checksum);
	return 0;
}

int main(int argc, char *argv[])
{
	argv++;
	argc--;

	if (argc < 1) {
		return Help();
	}

	string Command = *argv++; argc--;

	if (Command == "blank") {
		return main_blank(argc, argv);
	}

	if (Command == "add-raw") {
		return main_add_raw(argc, argv);
	}

	if (Command == "checksum") {
		return main_checksum(argc, argv);
	}

	return Help();
}
