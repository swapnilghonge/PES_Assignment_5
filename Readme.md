PES Assignment - 5 </br>
Optimization of PBKDF2</br>

Steps taken:
Used memcpy() and memset() in place loops used for copying and setting the data.</br>
Used resgister keyword only once</br>
Used techniques like bswap, loop unrolling.</br>

New time is 2660msecs

Previously</br>

static void ISHAProcessMessageBlock()</br>

for(t = 0; t < 16; t++)</br>
  {</br>
    W[t] = ((uint32_t) ctx->MBlock[t * 4]) << 24;</br>
    W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 1]) << 16;</br>
    W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 2]) << 8;</br>
    W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 3]);</br>
  }</br>

  for(t = 0; t < 16; t++)</br>
  {</br>
    temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t];</br>
    temp &= 0xFFFFFFFF;</br>
    E = D;</br>
    D = C;</br>
    C = ISHACircularShift(30,B);</br>
    B = A;</br>
    A = temp;</br>
  }</br>

Now</br>
for(t = 0; t < 16; t++)</br>
  {</br>
    temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (</br>
    		(((uint32_t) ctx->MBlock[t*4]) << shift_bit_24_times) |</br>
    		(((uint32_t) ctx->MBlock[t*4+1]) << shift_bit_16_times) |</br>
    		(((uint32_t) ctx->MBlock[t*4+2]) << shift_bit_8_times) |</br>
			 ((uint32_t) ctx->MBlock[t*4+3])</br>

    );</br>

Previously</br>
static void ISHAPadMessage(ISHAContext *ctx)</br>
{
  if (ctx->MB_Idx > 55)</br>
  {</br>
    ctx->MBlock[ctx->MB_Idx++] = 0x80;</br>
    while(ctx->MB_Idx < 64)</br>
    {</br>
      ctx->MBlock[ctx->MB_Idx++] = 0;</br>
    }</br>

    ISHAProcessMessageBlock(ctx);</br>

    while(ctx->MB_Idx < 56)</br>
    {</br>
      ctx->MBlock[ctx->MB_Idx++] = 0;</br>
    }</br>
  }</br>
  else</br>
  {</br>
    ctx->MBlock[ctx->MB_Idx++] = 0x80;</br>
    while(ctx->MB_Idx < 56)</br>
    {</br>
      ctx->MBlock[ctx->MB_Idx++] = 0;</br>
    }</br>
  }</br>

NOW </br>

static void ISHAPadMessage(ISHAContext *ctx)</br>
{</br>
  if (ctx->MB_Idx > 55)</br>
  {</br>
    ctx->MBlock[ctx->MB_Idx++] = 0x80;</br>

    memset(ctx->MBlock + ctx->MB_Idx, 0, ISHA_BLOCKLEN - ctx->MB_Idx);</br>

    ISHAProcessMessageBlock(ctx);</br>


    memset(ctx->MBlock, 0, ISHA_BLOCKLEN - 6);</br>
  }</br>
  else</br>
  {</br>
    ctx->MBlock[ctx->MB_Idx++] = 0x80;</br>

    memset(ctx->MBlock + ctx->MB_Idx, 0, ISHA_BLOCKLEN- 5 - ctx->MB_Idx);</br>
  }</br>


Previously </br>
void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)</br>
{</br>
  if (!length)</br>
  {</br>
    return;</br>
  }</br>

  if (ctx->Computed || ctx->Corrupted)</br>
  {</br>
    ctx->Corrupted = 1;</br>
    return;</br>
  }
</br>
  while(length-- && !ctx->Corrupted)</br>
  {</br>
    ctx->MBlock[ctx->MB_Idx++] = (*message_array & 0xFF);</br>

    ctx->Length_Low += 8;</br>
    /* Force it to 32 bits */</br>
    ctx->Length_Low &= 0xFFFFFFFF;</br>
    if (ctx->Length_Low == 0)</br>
    {</br>
      ctx->Length_High++;</br>
      /* Force it to 32 bits */</br>
      ctx->Length_High &= 0xFFFFFFFF;</br>
      if (ctx->Length_High == 0)</br>
      {</br>
        /* Message is too long */</br>
        ctx->Corrupted = 1;</br>
      }</br>
    }</br>

    if (ctx->MB_Idx == 64)</br>
    {</br>
      ISHAProcessMessageBlock(ctx);</br>
    }</br>

    message_array++;</br>
  }</br>
}</br>

NOW</br>

void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)</br>
{</br>
  int temp = 0;</br>
  if (!length) // error checking for length</br>
  {</br>
    return;</br>
  }
</br>
  ctx->buffer_len = ctx->buffer_len+ length; //transferring the value of length + ctx->buffer in ctx->buffer</br>

  while(length)</br>
  {</br>
	  temp = length;</br>
	if( (ISHA_BLOCKLEN - ctx->MB_Idx) < length) // if difference of ISHA Block and Index of array is less then length</br>

	{</br>
		temp = ISHA_BLOCKLEN - ctx->MB_Idx; // then the temp gets the value difference of ISHA block and Index</br>
	}</br>

	memcpy(ctx->MBlock + ctx->MB_Idx, message_array, temp); // Copying the value message array to ctx block</br>
	ctx->MB_Idx = ctx->MB_Idx +temp;</br>
	message_array = message_array + temp; //increment the message array by temp value</br>
	length = length-temp; // decrement of length by temp value</br>


    if (ctx->MB_Idx == ISHA_BLOCKLEN) // if the Index is equal to block the send the ctx value to process message block</br>
    {</br>
      ISHAProcessMessageBlock(ctx);</br>
    }</br>
  }</br>

}</br>


Previously</br>
void hmac_isha ()</br>

else {</br>
    // key_len <= ISHA_BLOCKLEN; copy key into keypad, zero pad the result</br>
    for (i=0; i<key_len; i++)</br>
      keypad[i] = key[i];</br>
    for(i=key_len; i<ISHA_BLOCKLEN; i++)</br>
      keypad[i] = 0x00;</br>

NOW:</br>
else {
    // key_len <= ISHA_BLOCKLEN; copy key into keypad, zero pad the result</br>
	  
	  memcpy( keypad, key, key_len );</br>
	  memset( keypad + key_len, 0x00, ISHA_BLOCKLEN );</br>

Previously</br>
void F()</br>
for (int i=0; i<ISHA_DIGESTLEN; i++)</br>
    result[i] = temp[i];</br>

  for (int j=1; j<iter; j++) {</br>
    hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);</br>
    for (int i=0; i<ISHA_DIGESTLEN; i++)</br>
      result[i] ^= temp[i];</br>
NOW:</br>
int j = 1;</br>
  while(j<iter) {</br>
	  // Perform inner ISHA</br>
	
	  ISHAReset(&ctx);</br>
	  ISHAInput(&ctx, ipad, ISHA_BLOCKLEN);</br>
	  ISHAInput(&ctx, temp, ISHA_DIGESTLEN);</br>
	  ISHAResult(&ctx, inner_digest);</br>

	  // perform outer ISHA</br>
	  ISHAReset(&ctx);</br>
	  ISHAInput(&ctx, opad, </br>
	  ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN);</br>
	  ISHAResult(&ctx, temp);</br>
	  int i = 0;</br>
	  while(i<ISHA_DIGESTLEN) {</br>
		result[i] ^= temp[i];</br>
		i++;</br>
	  }</br>
	  j++;</br>
  }
</br>