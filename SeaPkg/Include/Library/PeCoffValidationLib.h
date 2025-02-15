#ifndef BASE_PECOFF_VALIDATION_LIB_H_
#define BASE_PECOFF_VALIDATION_LIB_H_

#define IMAGE_VALIDATION_ENTRY_TYPE_NONE      0x00000000
#define IMAGE_VALIDATION_ENTRY_TYPE_NON_ZERO  0x00000001
#define IMAGE_VALIDATION_ENTRY_TYPE_CONTENT   0x00000002
#define IMAGE_VALIDATION_ENTRY_TYPE_MEM_ATTR  0x00000003
#define IMAGE_VALIDATION_ENTRY_TYPE_SELF_REF  0x00000004
#define IMAGE_VALIDATION_ENTRY_TYPE_POINTER   0x00000005

#define IMAGE_VALIDATION_DATA_SIGNATURE   SIGNATURE_32 ('V', 'A', 'L', 'D')
#define IMAGE_VALIDATION_ENTRY_SIGNATURE  SIGNATURE_32 ('E', 'N', 'T', 'R')

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
  UINT32    Offset;           // Offset to the data to validate in the loaded image.
  UINT32    Size;             // Size (in bytes) of the data to validate in the loaded image.
  UINT32    ValidationType;   // The Validation type to be performed on this data.
  UINT32    OffsetToDefault;  // Offset to the default value in the aux file this header is contained in.
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

  @param[in] TargetImage    The pointer to the target image buffer.
  @param[in] Hdr            The header of the validation entry.
  @param[in] AuxEndAddress  The address of the end of the auxiliary file.

  @return EFI_SUCCESS             The target image passes the validation.
  @return EFI_COMPROMISED_DATA    The content to match against overflows the auxiliary file.
  @return EFI_SECURITY_VIOLATION  The specified buffer in the target image does not match the reference data.
**/
EFI_STATUS
PeCoffImageValidationContent (
  IN VOID                           *TargetImage,
  IN IMAGE_VALIDATION_ENTRY_HEADER  *Hdr,
  IN UINTN                          AuxEndAddress
);

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  belongs to a user page that is mapped inside MM and teh page attributes match the requirements specified
  by the validation entry.

  @param[in] TargetImage    The pointer to the target image buffer.
  @param[in] Hdr            The header of the validation entry.
  @param[in] PageTableBase  The base address of the page table.
    
  @returns EFI_SUCCESS             The target image passes the validation.
  @returns EFI_INVALID_PARAMETER   The validation entry has invalid must have and must not have attributes.
  @returns EFI_INVALID_PARAMETER   The validation entry data size is invalid. It must be a pointer size.
  @returns EFI_SECURITY_VIOLATION  The target image does not meet the memory attribute requirements.
**/
EFI_STATUS
PeCoffImageValidationMemAttr (
  IN VOID                           *TargetImage,
  IN IMAGE_VALIDATION_ENTRY_HEADER  *Hdr,
  IN EFI_PHYSICAL_ADDRESS           PageTableBase
);

#endif // BASE_PECOFF_VALIDATION_LIB_H_