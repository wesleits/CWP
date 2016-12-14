void showHex(unsigned char* data, int Size)
{
	unsigned char a, line[17], c;

	//loop over each character and print
	for (int i = 0; i < Size; i++)
	{
		c = data[i];

		//Print the hex value for every character , with a space
		printf(" %.2x", (unsigned int)c);

		//Add the character to data line
		a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';

		line[i % 16] = a;

		//if last character of a line , then print the line - 16 characters in 1 line
		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)
		{
			line[i % 16 + 1] = '\0';

			//print a big gap of 10 characters between hex and characters
			printf("          ");



			printf("%s \n", line);
		}
	}
}


 
 
__device__ int cudaMemCmp(const void* s1, const void* s2, size_t n)
{
	const unsigned char *p1 = (const unsigned char *)s1, *p2 = (const unsigned char *)s2;
	while (n--)
		if (*p1 != *p2)
			return *p1 - *p2;
		else
			p1++, p2++;
	return 0;
}