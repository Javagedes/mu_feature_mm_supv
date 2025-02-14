/** @file
  TODO
**/
#ifndef BASE_PECOFF_VALIDATION_LIB_H_
#define BASE_PECOFF_VALIDATION_LIB_H_

#pragma pack(1)

typedef struct {
  UINT32    Signature;
  UINT32    Offset;
} KEY_SYMBOL;

typedef struct {
  UINT32    HeaderSignature;
  UINT32    Size;
  UINT32    EntryCount;
  UINT32    OffsetToFirstEntry;
  UINT32    OffsetToFirstDefault;
  UINT32    KeySymbolCount;
  UINT32    OffsetToFirstKeySymbol;
} IMAGE_VALIDATION_DATA_HEADER;

typedef struct {
  UINT32    EntrySignature;
  UINT32    Offset; // Offset to the start of the target image
  UINT32    Size;   // Size of this entry
  UINT32    ValidationType;
  UINT32    OffsetToDefault;
} IMAGE_VALIDATION_ENTRY_HEADER;

typedef struct {
  IMAGE_VALIDATION_ENTRY_HEADER    Header;
  UINT8                            TargetContent[];
} IMAGE_VALIDATION_CONTENT;

typedef struct {
  IMAGE_VALIDATION_ENTRY_HEADER    Header;
  UINT64                           TargetMemorySize;
  UINT64                           TargetMemoryAttributeMustHave;
  UINT64                           TargetMemoryAttributeMustNotHave;
} IMAGE_VALIDATION_MEM_ATTR;

typedef struct {
  IMAGE_VALIDATION_ENTRY_HEADER    Header;
  UINT32                           TargetOffset;
} IMAGE_VALIDATION_SELF_REF;

#pragma pack()

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  is not a zero buffer.

  @param[in] TargetImage  The pointer to the target image buffer.
  @param[in] Hdr          The header of the validation entry.

  @return EFI_SUCCESS             The target image passes the validation.
  @return EFI_SECURITY_VIOLATION  The specified buffer in the target image is all zero.
**/
EFI_STATUS
PeCoffImageValidationNonZero (
    IN VOID                           *TargetImage,
    IN IMAGE_VALIDATION_ENTRY_HEADER  *Hdr
);

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  is the same as the content in the reference data.

  @param[in] TargetImage  The pointer to the target image buffer.
  @param[in] Hdr          The header of the validation entry.

  @return EFI_SUCCESS             The target image passes the validation.
  @return EFI_SECURITY_VIOLATION  The specified buffer in the target image does not match the reference data.
**/
EFI_STATUS
PeCoffImageValidationContent (
  IN VOID                      *TargetImage,
  IN IMAGE_VALIDATION_ENTRY_HEADER  *Hdr
);

#endif // BASE_PECOFF_LIB_NEGATIVE_H_