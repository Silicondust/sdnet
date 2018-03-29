
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <istream>
#include "DoubleEndedMemory.h"

#if !defined(DOUBLE_ENDED_MEMORY_ALLOC_SIZE)
#define DOUBLE_ENDED_MEMORY_ALLOC_SIZE 4096
#endif

TDoubleEndedMemory::TDoubleEndedMemory()
{
	Buffer = NULL;
	Limit = NULL;
	Begin = NULL;
	End = NULL;
}

TDoubleEndedMemory::~TDoubleEndedMemory()
{
	if (Buffer) {
		free(Buffer);
	}
}

void TDoubleEndedMemory::AppendAlloc(size_t Length)
{
	size_t SpaceAvailable = Limit - End;
	if (SpaceAvailable >= Length) {
		return;
	}

	size_t ExistingBeginOffset = Begin - Buffer;
	size_t ExistingEndOffset = End - Buffer;

	size_t AppendAllocSize = Length - SpaceAvailable;
	AppendAllocSize = (AppendAllocSize + DOUBLE_ENDED_MEMORY_ALLOC_SIZE - 1) / DOUBLE_ENDED_MEMORY_ALLOC_SIZE * DOUBLE_ENDED_MEMORY_ALLOC_SIZE;

	size_t ExistingBufferSize = Limit - Buffer;
	size_t NewBufferSize = ExistingBufferSize + AppendAllocSize;
	uint8_t *NewBuffer = (uint8_t *)realloc(Buffer, NewBufferSize);
	if (!NewBuffer) {
		throw "out of memory";
	}

	if (NewBuffer != Buffer) {
		Buffer = NewBuffer;
		Begin = NewBuffer + ExistingBeginOffset;
		End = NewBuffer + ExistingEndOffset;
	}

	Limit = Buffer + NewBufferSize;
}

void TDoubleEndedMemory::PrependAlloc(size_t Length)
{
	size_t SpaceAvailable = Begin - Buffer;
	if (SpaceAvailable >= Length) {
		return;
	}

	size_t PrependAllocSize = Length - SpaceAvailable;
	PrependAllocSize = (PrependAllocSize + DOUBLE_ENDED_MEMORY_ALLOC_SIZE - 1) / DOUBLE_ENDED_MEMORY_ALLOC_SIZE * DOUBLE_ENDED_MEMORY_ALLOC_SIZE;

	size_t ExistingBufferSize = Limit - Buffer;
	size_t NewBufferSize = PrependAllocSize + ExistingBufferSize;
	uint8_t *NewBuffer = (uint8_t *)malloc(NewBufferSize);
	if (!NewBuffer) {
		throw "out of memory";
	}

	size_t ExistingBeginOffset = Begin - Buffer;
	size_t ExistingEndOffset = End - Buffer;

	if (End > Begin) {
		memcpy(NewBuffer + PrependAllocSize + ExistingBeginOffset, Begin, End - Begin);
	}
	if (Buffer) {
		free(Buffer);
	}

	Buffer = NewBuffer;
	Limit = NewBuffer + NewBufferSize;
	Begin = NewBuffer + PrependAllocSize + ExistingBeginOffset;
	End = NewBuffer + PrependAllocSize + ExistingEndOffset;
}

size_t TDoubleEndedMemory::Length()
{
	return End - Begin;
}

void TDoubleEndedMemory::AppendU8(uint8_t v)
{
	AppendAlloc(1);
	*End++ = v;
}

void TDoubleEndedMemory::AppendU16(uint16_t v)
{
	AppendAlloc(2);
	*End++ = v >> 8;
	*End++ = v >> 0;
}

void TDoubleEndedMemory::AppendU32(uint32_t v)
{
	AppendAlloc(4);
	*End++ = v >> 24;
	*End++ = v >> 16;
	*End++ = v >> 8;
	*End++ = v >> 0;
}

void TDoubleEndedMemory::AppendFill(uint8_t v, size_t Count)
{
	AppendAlloc(Count);
	memset(End, v, Count);
	End += Count;
}

void TDoubleEndedMemory::AppendMem(const void *Ptr, size_t Length)
{
	AppendAlloc(Length);
	memcpy(End, Ptr, Length);
	End += Length;
}

void TDoubleEndedMemory::AppendStream(std::istream &Stream, size_t Length)
{
	AppendAlloc(Length);
	Stream.read((char *)End, Length);
	End += Length;
}

void TDoubleEndedMemory::PrependU8(uint8_t v)
{
	PrependAlloc(1);
	*(--Begin) = v;
}

void TDoubleEndedMemory::PrependU16(uint16_t v)
{
	PrependAlloc(2);
	*(--Begin) = v >> 0;
	*(--Begin) = v >> 8;
}

void TDoubleEndedMemory::PrependU32(uint32_t v)
{
	PrependAlloc(4);
	*(--Begin) = v >> 0;
	*(--Begin) = v >> 8;
	*(--Begin) = v >> 16;
	*(--Begin) = v >> 24;
}

void TDoubleEndedMemory::PrependMem(const void *Ptr, size_t Length)
{
	PrependAlloc(Length);
	Begin -= Length;
	memcpy(Begin, Ptr, Length);
}

void TDoubleEndedMemory::PrependStream(std::istream &Stream, size_t Length)
{
	PrependAlloc(Length);
	Begin -= Length;
	Stream.read((char *)Begin, Length);
}
