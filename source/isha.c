/*
 * isha.c
 *
 * A completely insecure and bad hashing algorithm, based loosely on
 * SHA-1 (which is itself no longer considered a good hashing
 * algorithm)
 *
 * Based on code for sha1 processing from Paul E. Jones, available at
 * https://www.packetizer.com/security/sha1/
 */

#include "isha.h"
#include <string.h>



/*
 * circular shift macro
 */
#define ISHACircularShift(bits,word) \
  ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))


/*  
 * Processes the next 512 bits of the message stored in the MBlock
 * array.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
static void ISHAProcessMessageBlock(ISHAContext *ctx)
{
  uint32_t temp;
  int t;
  //uint32_t W[16];
  register uint32_t A;
  uint32_t B, C, D, E;

  A = ctx->MD[0];
  B = ctx->MD[1];
  C = ctx->MD[2];
  D = ctx->MD[3];
  E = ctx->MD[4];


  for(t = 0; t < 16; t++)
  {
//##### Change No.1  Replacing the value of W[t] in the function #####
    temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (
    		(((uint32_t) ctx->MBlock[t*4]) << shift_bit_24_times) |
    		(((uint32_t) ctx->MBlock[t*4+1]) << shift_bit_16_times) |
    		(((uint32_t) ctx->MBlock[t*4+2]) << shift_bit_8_times) |
			 ((uint32_t) ctx->MBlock[t*4+3])

    );

    temp &= 0xFFFFFFFF;
    E = D;
    D = C;
    C = ISHACircularShift(30,B);
    B = A;
    A = temp;
  }

  ctx->MD[0] += ( A) ;
   ctx->MD[1] += ( B) ;
   ctx->MD[2] += ( C) ;
   ctx->MD[3] += ( D) ;
   ctx->MD[4] += ( E) ;

  ctx->MB_Idx = 0;
}


/*  
 * The message must be padded to an even 512 bits.  The first padding
 * bit must be a '1'.  The last 64 bits represent the length of the
 * original message.  All bits in between should be 0. This function
 * will pad the message according to those rules by filling the MBlock
 * array accordingly. It will also call ISHAProcessMessageBlock()
 * appropriately. When it returns, it can be assumed that the message
 * digest has been computed.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
static void ISHAPadMessage(ISHAContext *ctx)
{
  /*
   *  Check to see if the current message block is too small to hold
   *  the initial padding bits and length.  If so, we will pad the
   *  block, process it, and then continue padding into a second
   *  block.
   */
  if (ctx->MB_Idx > 55)
  {
    ctx->MBlock[ctx->MB_Idx++] = 0x80;

    //##### Change No.2 Copying the character to ctx->Mblock+ctx->mb_idx #####
    memset(ctx->MBlock + ctx->MB_Idx, 0, ISHA_BLOCKLEN - ctx->MB_Idx);

    ISHAProcessMessageBlock(ctx);


    //##### Change No.3 Copying the character to ctx->Mblock+ctx->mb_idx #####
    memset(ctx->MBlock, 0, ISHA_BLOCKLEN - 6);
  }
  else
  {
    ctx->MBlock[ctx->MB_Idx++] = 0x80;

    //##### Change No.3 Copying the character to ctx->Mblock+ctx->mb_idx #####
    memset(ctx->MBlock + ctx->MB_Idx, 0, ISHA_BLOCKLEN- 5 - ctx->MB_Idx);
  }

  /*
   *  Store the message length as the last 8 octets
   */
  	  ctx->MBlock[59] = (ctx->buffer_len >> Const1) & mask;
      ctx->MBlock[60] = (ctx->buffer_len >> Const2) & mask;
      ctx->MBlock[61] = (ctx->buffer_len >> Const3) & mask;
      ctx->MBlock[62] = (ctx->buffer_len >> Const4) & mask;
      ctx->MBlock[63] = (ctx->buffer_len << Const5) & mask;

  ISHAProcessMessageBlock(ctx);
}


void ISHAReset(ISHAContext *ctx)
{
  //ctx->Length_Low  = 0;
  //ctx->Length_High = 0;

  ctx->MB_Idx      = 0;
  ctx->buffer_len = 0;

  ctx->MD[0]       = 0x67452301;
  ctx->MD[1]       = 0xEFCDAB89;
  ctx->MD[2]       = 0x98BADCFE;
  ctx->MD[3]       = 0x10325476;
  ctx->MD[4]       = 0xC3D2E1F0;

  ctx->Computed    = 0;
  ctx->Corrupted   = 0;
}


void ISHAResult(ISHAContext *ctx, uint8_t *digest_out)
{
  if (ctx->Corrupted)
  {
    return;
  }

  if (!ctx->Computed)
  {
    ISHAPadMessage(ctx);
    ctx->Computed = 1;
  }

  //##### Change No.4 using bswap32 to reversing the bits in digest_out #####
  	  	 *((uint32_t *)(digest_out))=__builtin_bswap32(ctx->MD[0]);
    	*((uint32_t *)(digest_out + 4))=__builtin_bswap32(ctx->MD[1]);
    	*((uint32_t *)(digest_out + 8))=__builtin_bswap32(ctx->MD[2]);
    	*((uint32_t *)(digest_out + 12))=__builtin_bswap32(ctx->MD[3]);
    	*((uint32_t *)(digest_out + 16))=__builtin_bswap32(ctx->MD[4]);

  return;
}

//##### Change No.5 redefining the ISHA Input function #####
void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)
{
  int temp = 0;
  if (!length) // error checking for length
  {
    return;
  }

  ctx->buffer_len = ctx->buffer_len+ length; //transferring the value of length + ctx->buffer in ctx->buffer

  while(length)
  {
	  temp = length;
	if( (ISHA_BLOCKLEN - ctx->MB_Idx) < length) // if difference of ISHA Block and Index of array is less then length

	{
		temp = ISHA_BLOCKLEN - ctx->MB_Idx; // then the temp gets the value difference of ISHA block and Index
	}

	memcpy(ctx->MBlock + ctx->MB_Idx, message_array, temp); // Copying the value message array to ctx block
	ctx->MB_Idx = ctx->MB_Idx +temp;
	message_array = message_array + temp; //increment the message array by temp value
	length = length-temp; // decrement of length by temp value


    if (ctx->MB_Idx == ISHA_BLOCKLEN) // if the Index is equal to block the send the ctx value to process message block
    {
      ISHAProcessMessageBlock(ctx);
    }
  }

}

