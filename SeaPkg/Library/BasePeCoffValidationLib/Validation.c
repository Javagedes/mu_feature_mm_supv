/** @file
  Validation functions for PE/COFF image against a reference auxiliary file. This logic is exposed as an EDKII library
  to allow for simple host based unit testing of the validation logic.
*/
#include <Uefi.h>
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PeCoffValidationLib.h>

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
)
{
  if (IsZeroBuffer ((UINT8 *)TargetImage + Hdr->Offset, Hdr->Size)) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry range 0x%p: 0x%x is all 0s\n", __func__, (UINT8 *)TargetImage + Hdr->Offset, Hdr->Size));
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  is the same as the content in the reference data.

  @param[in] TargetImage  The pointer to the target image buffer.
  @param[in] Hdr          The header of the validation entry.
  @param[in] AuxSize      The size of the reference data buffer.

  @return EFI_SUCCESS             The target image passes the validation.
  @return EFI_SECURITY_VIOLATION  The specified buffer in the target image does not match the reference data.
**/
EFI_STATUS
PeCoffImageValidationContent (
  IN VOID                           *TargetImage,
  IN IMAGE_VALIDATION_ENTRY_HEADER  *Hdr,
  IN UINTN                          AuxSize
)
{
  IMAGE_VALIDATION_CONTENT *ContentHdr = (IMAGE_VALIDATION_CONTENT *)Hdr;

  if (sizeof (*ContentHdr) + Hdr->Size > AuxSize) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry range 0x%p: 0x%x exceeds reference data limit 0x%x\n", __func__, Hdr, Hdr->Size, AuxSize));
    return EFI_COMPROMISED_DATA;
  }

  if (CompareMem ((UINT8 *)TargetImage + Hdr->Offset, ContentHdr->TargetContent, Hdr->Size) != 0) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry range 0x%p: 0x%x does not match input content at 0x%p\n", __func__, Hdr, Hdr->Size, ContentHdr->TargetContent));
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

/**
  Validates the page where the address dented by [Hdr->Offset] is located belongs to a user page that is mapped inside MM and that
  the memory attributes of the page meet the requirements as denoted by TargetMemoryAttributeMustHave and TargetMemoryAttributeMustNotHave.

  @param[in]
**/