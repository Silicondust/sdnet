
class TDoubleEndedMemory {
public:
	TDoubleEndedMemory();
	~TDoubleEndedMemory();

	uint8_t *Begin;
	uint8_t *End;

	size_t Length();

	void AppendU8(uint8_t v);
	void AppendU16(uint16_t v);
	void AppendU32(uint32_t v);
	void AppendFill(uint8_t v, size_t Count);
	void AppendMem(const void *Ptr, size_t Length);
	void AppendStream(std::istream &Stream, size_t Length);

	void PrependU8(uint8_t v);
	void PrependU16(uint16_t v);
	void PrependU32(uint32_t v);
	void PrependMem(const void *Ptr, size_t Length);
	void PrependStream(std::istream &Stream, size_t Length);

protected:
	uint8_t *Buffer;
	uint8_t *Limit;

	void AppendAlloc(size_t Length);
	void PrependAlloc(size_t Length);
};
