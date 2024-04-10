#include "axolotl.h"

void axolotl(char *name, Axolotl *obj)
{
	obj->my_identity = name;
	User *user = new_user(obj->my_identity);
	memmove(obj->DHIs_priv, user->secret_key, 32);
	memmove(obj->DHIs, user->public_key, 32);	

	return;
}

void initState(Axolotl *obj, char *name, unsigned char *B, unsigned char *a0, unsigned char *B0, unsigned char *DHR)
{
	unsigned char key[160];
	if (verify(name, B))
	{
		obj->other_identity = name;
		memmove(obj->DHIr, B, 32);		

		unsigned char *masterkey = keyAgreement(obj->mode, obj->DHIs_priv, a0, B, B0);
		if(crypto_pwhash_scryptsalsa208sha256(key, 160, masterkey, 32, masterkey, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0)
		{
			printf("Key derivation failed!\n");
			remove(key);
			return;
		}
		if (obj->mode == 0)
		{
			memmove(obj->RK, key, 32);
			memmove(obj->HKr, key + 32, 32);
			memmove(obj->NHKs, key + 64, 32);
			memmove(obj->NHKr, key + 96, 32);
			memmove(obj->CKr, key + 128, 32);
			obj->HKs[0] = '\0';
			obj->CKs[0] = '\0';
			obj->DHRs_priv[0] = '\0';
			obj->DHRs[0] = '\0';
			memmove(obj->DHRr, DHR, 32);			
			obj->Ns = 0;
			obj->Nr = 0;
			obj->PNs = 0;
			obj->ratchet_flag = true;
		}
		else
		{
			memmove(obj->RK, key, 32);
			memmove(obj->HKs, key + 32, 32);
			memmove(obj->NHKr, key + 64, 32);
			memmove(obj->NHKs, key + 96, 32);
			memmove(obj->CKs, key + 128, 32);
			obj->HKr[0] = '\0';
			obj->CKr[0] = '\0';
			obj->DHRr[0] = '\0';
			obj->Ns = 0;
			obj->Nr = 0;
			obj->PNs = 0;
			obj->ratchet_flag = false;
		}
	}
	else{
		printf("Be careful that the identity key doesn't match the identity %s in the server.\nPress Enter to exit...\n", name);
		remove(key);
		return;
	}

	remove(key);
	return;
}

unsigned char *keyAgreement(int mode, unsigned char *a, unsigned char *a0, unsigned char *B, unsigned char *B0)
{
	unsigned char DH1[32], DH2[32], DH3[32];
	unsigned char shared_key[96];
	unsigned char master_key[32];
	if (mode == 0)
	{
		crypto_scalarmult(DH1, a, B0);
		crypto_scalarmult(DH2, a0, B);
		crypto_scalarmult(DH3, a0, B0);
	}
	else
	{
		crypto_scalarmult(DH1, a0, B);
		crypto_scalarmult(DH2, a, B0);
		crypto_scalarmult(DH3, a0, B0);
	}

	memmove(shared_key, DH1, 32);
	memmove(shared_key + 32, DH2, 32);
	memmove(shared_key + 64, DH3, 32);

	crypto_hash_sha256(master_key, shared_key, 96);

	remove(DH1);
	remove(DH2);
	remove(DH3);
	remove(shared_key);

	return master_key;
}

EphemeralKey *generateEphemeralKey()
{
	EphemeralKey *ephemeralKey;
	ephemeralKey = (EphemeralKey*)malloc(sizeof(EphemeralKey));

	crypto_box_keypair(ephemeralKey->public_key, ephemeralKey->secret_key);

	return ephemeralKey;
}

void getFilename(char *text, char *name1, char *name2)
{
	int i, j;
	for (i = 0, j = 0; name1[j] != '\0'; i++, j++)
		text[i] = name1[j];
	for (j = 0; name2[j] != '\0'; i++, j++)
		text[i] = name2[j];
	text[i++] = '.';
	text[i++] = 't';
	text[i++] = 'x';
	text[i++] = 't';
	text[i] = '\0';

	return;
}

int verify(char *name, unsigned char *identity_key)
{
	FILE *fp;
	char namet[20];
	unsigned char identity[35];
	int i = 0;
	fp = fopen("users.txt", "r");
	if (fp == NULL)
	{
		printf("Error in opening file!\n");
		remove(namet);
		remove(identity);
		return 0;
	}
	fscanf(fp, "%s", namet);
	while (strcmp(namet, name) != 0 && !feof(fp))
	{
		while (fgetc(fp) != '\n' && !feof(fp));
		fscanf(fp, "%s", namet);
	}
	if (!feof(fp))
	{
		i = 0;
		fgetc(fp);  //parse the space
		while (fgetc(fp) != '\n' && !feof(fp))
		{
			fscanf(fp, "0x%2x", &identity[i]);
			i++;
		}

		for (i = 0; i < 32; i++)
		{
			if (identity_key[i] != identity[i])
				break;
		}
	}
	else
	{
		fclose(fp);
		remove(namet);
		remove(identity);
		return 0;
	}

	if (i < 32)
	{
		fclose(fp);
		remove(namet);
		remove(identity);
		return 0;
	}

	fclose(fp);
	remove(namet);
	remove(identity);
	return 1;
}

void saveState(Axolotl *obj)
{
	int i;
	char text[50]; //the name of the file
	getFilename(text, obj->my_identity, obj->other_identity);
	FILE *fp;
	fp = fopen(text, "w");
	if (fp == NULL)
	{
		printf("Error in opening file!\n");
		return;
	}

	fprintf(fp, "# This is a record file of the communication between %s and %s.\n", obj->my_identity, obj->other_identity);
	fprintf(fp, "%s\n", obj->my_identity);
	fprintf(fp, "%s\n", obj->other_identity);
	
	for (i = 0; i < 32; ++i)
	{
		fprintf(fp, ",0x%02x", (unsigned int)obj->RK[i]);
	}
	fprintf(fp, "#RK\n");

	if (obj->HKs[0] != '\0')
	{
		for (i = 0; i < 32; ++i)
		{
			fprintf(fp, ",0x%02x", (unsigned int)obj->HKs[i]);
		}
		fprintf(fp, "#HKs\n");
	}
	else{
		fputc('\n', fp);
	}

	if (obj->HKr[0] != '\0')
	{
		for (i = 0; i < 32; ++i)
		{
			fprintf(fp, ",0x%02x", (unsigned int)obj->HKr[i]);
		}
		fprintf(fp, "#HKr\n");
	}
	else{
		fputc('\n', fp);
	}
	
	for (i = 0; i < 32; ++i)
	{
		fprintf(fp, ",0x%02x", (unsigned int)obj->NHKs[i]);
	}
	fprintf(fp, "#NHKs\n");
	
	for (i = 0; i < 32; ++i)
	{
		fprintf(fp, ",0x%02x", (unsigned int)obj->NHKr[i]);
	}
	fprintf(fp, "#NHKr\n");
	
	if (obj->CKs[0] != '\0')
	{
		for (i = 0; i < 32; ++i)
		{
			fprintf(fp, ",0x%02x", (unsigned int)obj->CKs[i]);
		}
		fprintf(fp, "#CKs\n");
	}
	else{
		fputc('\n', fp);
	}
	
	if (obj->CKr[0] != '\0')
	{
		for (i = 0; i < 32; ++i)
		{
			fprintf(fp, ",0x%02x", (unsigned int)obj->CKr[i]);
		}
		fprintf(fp, "#CKr\n");
	}
	else{
		fputc('\n', fp);
	}

	for (i = 0; i < 32; ++i)
	{
		fprintf(fp, ",0x%02x", (unsigned int)obj->DHIr[i]);
	}
	fprintf(fp, "#DHIr\n");

	if (obj->DHRs_priv[0] != '\0')
	{
		for (i = 0; i < 32; ++i)
		{
			fprintf(fp, ",0x%02x", (unsigned int)obj->DHRs_priv[i]);
		}
		fprintf(fp, "#DHRs_priv\n");
	}
	else{
		fputc('\n', fp);
	}

	if (obj->DHRs[0] != '\0')
	{
		for (i = 0; i < 32; ++i)
		{
			fprintf(fp, ",0x%02x", (unsigned int)obj->DHRs[i]);
		}
		fprintf(fp, "#DHRs\n");
	}
	else{
		fputc('\n', fp);
	}

	if (obj->DHRr[0] != '\0')
	{
		for (i = 0; i < 32; ++i)
		{
			fprintf(fp, ",0x%02x", (unsigned int)obj->DHRr[i]);
		}
		fprintf(fp, "#DHRr\n");
	}
	else{
		fputc('\n', fp);
	}

	fprintf(fp, "%d %d %d ", obj->Ns, obj->Nr, obj->PNs);
	if (obj->ratchet_flag)
		fputc('1', fp);
	else
		fputc('0', fp);
	fprintf(fp, " %d\n", obj->mode);

	fclose(fp);
	printf("State saved!\n");

	return;
}

void loadState(Axolotl *obj, char *name)
{
	char namet[20];
	char text[50];
	int i = 0;
	User *user;
	printf("Input the name of the other side:");
	gets(namet);
	getFilename(text, name, namet);
	FILE *fp;

	if (fp = fopen(text, "r"))
	{
		while ((fgetc(fp)) != '\n');  //parse the first line
		obj->my_identity = (char*)malloc(20);
		fscanf(fp, "%s", obj->my_identity);
		obj->other_identity = (char*)malloc(20);
		fscanf(fp, "%s", obj->other_identity);
		fgetc(fp);
		while ((fgetc(fp)) != '#')
		{
			fscanf(fp, "0x%2x", &obj->RK[i]);
			i++;
		}
		i = 0;
		while ((fgetc(fp)) != '\n');

		if ((fgetc(fp)) != '\n')  //HKs may not exist
		{
			fscanf(fp, "0x%2x", &obj->HKs[i]);
			while ((fgetc(fp)) != '#')
			{
				i++;
				fscanf(fp, "0x%2x", &obj->HKs[i]);
			}
			while ((fgetc(fp)) != '\n');
		}
		else
			obj->HKs[0] = '\0';
		i = 0;
		
		if ((fgetc(fp)) != '\n')  //HKr may not exist
		{
			fscanf(fp, "0x%2x", &obj->HKr[i]);
			while ((fgetc(fp)) != '#')
			{
				i++;
				fscanf(fp, "0x%2x", &obj->HKr[i]);
			}
			while ((fgetc(fp)) != '\n');
		}
		else
			obj->HKr[0] = '\0';
		i = 0;
		
		while ((fgetc(fp)) != '#')
		{
			fscanf(fp, "0x%2x", &obj->NHKs[i]);
			i++;
		}
		i = 0;
		while ((fgetc(fp)) != '\n');

		while ((fgetc(fp)) != '#')
		{
			fscanf(fp, "0x%2x", &obj->NHKr[i]);
			i++;
		}
		i = 0;
		while ((fgetc(fp)) != '\n');

		if ((fgetc(fp)) != '\n')  //CKs may not exist
		{
			fscanf(fp, "0x%2x", &obj->CKs[i]);
			while ((fgetc(fp)) != '#')
			{
				i++;
				fscanf(fp, "0x%2x", &obj->CKs[i]);
			}
			while ((fgetc(fp)) != '\n');
		}
		else
			obj->CKs[0] = '\0';
		i = 0;
		
		if ((fgetc(fp)) != '\n')  //CKr may not exist
		{
			fscanf(fp, "0x%2x", &obj->CKr[i]);
			while ((fgetc(fp)) != '#')
			{
				i++;
				fscanf(fp, "0x%2x", &obj->CKr[i]);
			}
			while ((fgetc(fp)) != '\n');
		}
		else
			obj->CKr[0] = '\0';
		i = 0;

		while ((fgetc(fp)) != '#')
		{
			fscanf(fp, "0x%2x", &obj->DHIr[i]);
			i++;
		}
		i = 0;
		while ((fgetc(fp)) != '\n');

		if ((fgetc(fp)) != '\n')  //DHRs_priv and DHRs may not exist
		{
			fscanf(fp, "0x%2x", &obj->DHRs_priv[i]);
			while ((fgetc(fp)) != '#')
			{
				i++;
				fscanf(fp, "0x%2x", &obj->DHRs_priv[i]);
			}
			i = 0;
			while ((fgetc(fp)) != '\n');

			while ((fgetc(fp)) != '#')
			{
				fscanf(fp, "0x%02x", &obj->DHRs[i]);
				i++;
			}
			i = 0;
			while ((fgetc(fp)) != '\n');
		}
		else
		{
			fgetc(fp); //skip another '\n'
			obj->DHRs_priv[0] = '\0';
			obj->DHRs[0] = '\0';
		}


		if ((fgetc(fp)) != '\n')  //DHRr may not exist
		{
			fscanf(fp, "0x%2x", &obj->DHRr[i]);
			while ((fgetc(fp)) != '#')
			{
				i++;
				fscanf(fp, "0x%2x", &obj->DHRr[i]);
			}
			while ((fgetc(fp)) != '\n');
		}
		else
			obj->DHRr[0] = '\0';

		fscanf(fp, "%d %d %d ", &obj->Ns, &obj->Nr, &obj->PNs);
		i = fgetc(fp);
		if (i == '0')
			obj->ratchet_flag = false;
		if (i == '1')
			obj->ratchet_flag = true;
		fscanf(fp, " %d", &obj->mode);
	}
	else
	{
		printf("The conversation doesn't exit...\nPress Enter to exit...\n");
		return;
	}

	fclose(fp);

	user = new_user(obj->my_identity);
	memmove(obj->DHIs_priv, user->secret_key, 32);
	memmove(obj->DHIs, user->public_key, 32);
	if (!verify(obj->my_identity, obj->DHIs))
	{
		printf("The user doesn't match the given key. Loading failed...\nPress Enter to exit...\n");
		return;
	}
	printf("State loaded!\n");

	return;
}

void encrypt(Axolotl *obj, unsigned char *ciphertext, unsigned char *plaintext, int len)
{
	int i;
	unsigned char MK[32];
	unsigned char nonceM[NONCE_LENGTH], nonceH[NONCE_LENGTH];
	unsigned char header[HEADER_LENGTH], msg1[HEADER_LENGTH + MAC_LENGTH]; //use crypto_secretbox_easy to encrypt, which generates a 16-byte tag
	unsigned char *msg2 = (char *)malloc(len + MAC_LENGTH);
	unsigned char DH[32], key[96];

	if (obj->ratchet_flag)
	{   //generate a new ratchet key
		EphemeralKey *DHR = generateEphemeralKey();
		memmove(obj->DHRs_priv, DHR->secret_key, 32);
		memmove(obj->DHRs, DHR->public_key, 32);
		obj->PNs = obj->Ns;
		obj->Ns = 0;
		
		memmove(obj->HKs, obj->NHKs, 32);

		crypto_scalarmult(DH, obj->DHRs_priv, obj->DHRr); //DH(DHRs, DHRr)

		if(crypto_pwhash_scryptsalsa208sha256(key, 96, DH, 32, obj->RK, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0)
			{
				printf("Key derivation failed!\n");
				remove(MK);
				remove(DH);
				remove(key);
				return;
			}
		//derive the RK, NHKs and CKs
		memmove(obj->RK, key, 32);
		memmove(obj->NHKs, key + 32, 32);
		memmove(obj->CKs, key + 64, 32);
		
		obj->ratchet_flag = false;
	}

	crypto_auth_hmacsha256(MK, obj->CKs, 32, "0x00");  //compute the message key

	memmove(nonceH, obj->HKs, NONCE_LENGTH);
	memmove(nonceM, MK, NONCE_LENGTH);
	//take the first 24 bytes of the keys as the nonces, respectively 
	
	header2String(obj->Ns, obj->PNs, obj->DHRs, header);    //put Ns, PNs, DHRs into a string header
	crypto_secretbox_easy(msg1, header, HEADER_LENGTH, nonceH, obj->HKs);  //msg1 contains the encryption of the header
	crypto_secretbox_easy(msg2, plaintext, len, nonceM, MK);  //msg2 contains the encryption of the plaintext message

	obj->Ns++;  //increase the message number by one
	crypto_auth_hmacsha256(obj->CKs, obj->CKs, 32, "0x01");  //update the chain key

	for (i = 0; i < HEADER_LENGTH + MAC_LENGTH; i++)
		ciphertext[i] = msg1[i];  //copy the encryption of header to the first part of the ciphertext
	for (; i < HEADER_LENGTH + MAC_LENGTH + len + MAC_LENGTH; i++)
		ciphertext[i] = msg2[i- HEADER_LENGTH - MAC_LENGTH];  //copy the encryption of message to the second part of the ciphertext
	
	remove(MK);
	remove(DH);
	remove(key);

	return;
}

void decrypt(Axolotl *obj, unsigned char *ciphertext, unsigned char *plaintext, int len)
{
	unsigned char msg1[HEADER_LENGTH + MAC_LENGTH];   //the cipher of header part, 10 for Ns, 10 for PNs, 32 for DHRs, and 16-byte tag
	unsigned char header[HEADER_LENGTH];  //the decryption of header
	unsigned char *msg2 = (unsigned char *)malloc(len + MAC_LENGTH);  //the cipher of message part
	unsigned char MK[32];
	unsigned char nonceM[NONCE_LENGTH], nonceH[NONCE_LENGTH];
	int i, PNp = 0, Np = 0;
	unsigned char DHRp[32], CKp[32], CKpp[32], HKp[32], NHKp[32], RKp[32];
	unsigned char DH[32], key[96];

	FILE *fp;
	fp = fopen("log.txt", "a");
	if(fp == NULL)
	{
		printf("Create log file wrong!\n");
		return;
	}

	for (i = 0; i < HEADER_LENGTH + MAC_LENGTH; i++)
		msg1[i] = ciphertext[i];
	for (; i < len + HEADER_LENGTH + MAC_LENGTH + MAC_LENGTH; i++)
		msg2[i-HEADER_LENGTH-MAC_LENGTH] = ciphertext[i];

	//if find a correct key combination for this message in the stored keys, return
	if (trySkippedMK(plaintext, msg1, msg2, len, obj->my_identity, obj->other_identity))
	{
		remove(msg1);
		remove(header);
		remove(msg2);
		remove(MK);
		remove(nonceH);
		remove(nonceM);
		remove(DHRp);
		remove(CKp);
		remove(CKpp);
		remove(HKp);
		remove(NHKp);
		remove(RKp);
		remove(DH);
		remove(key);
		return;
	}
	
	memmove(nonceH, obj->HKr, NONCE_LENGTH);

	//try to decypt the header with HKr 
	if (crypto_secretbox_open_easy(header, msg1, HEADER_LENGTH + MAC_LENGTH, nonceH, obj->HKr) == 0)
	{
		string2Header(&Np, &PNp, DHRp, header); 

		stageSkippedMK(CKp, MK, obj->HKr, obj->Nr, Np, obj->CKr);
		memmove(nonceM, MK, NONCE_LENGTH);		
		
		if (crypto_secretbox_open_easy(plaintext, msg2, len + MAC_LENGTH, nonceM, MK) != 0)
		{
			printf("Undecipherable message!\n");
			remove(msg1);
			remove(header);
			remove(msg2);
			remove(MK);
			remove(nonceH);
			remove(nonceM);
			remove(DHRp);
			remove(CKp);
			remove(CKpp);
			remove(HKp);
			remove(NHKp);
			remove(RKp);
			remove(DH);
			remove(key);

			return;
		}
		fprintf(fp, "Decrypted!\n");
	}
	else
	{
		//try to decrypt the header with NHKr
		memmove(nonceH, obj->NHKr, NONCE_LENGTH);
		
		//if ratchet flag is true or decrypting the header with NHKr fails
		if (obj->ratchet_flag || (crypto_secretbox_open_easy(header, msg1, HEADER_LENGTH + MAC_LENGTH, nonceH, obj->NHKr) == -1))
		{
			printf("Undecipherable header and message!\n");
			remove(msg1);
			remove(header);
			remove(msg2);
			remove(MK);
			remove(nonceH);
			remove(nonceM);
			remove(DHRp);
			remove(CKp);
			remove(CKpp);
			remove(HKp);
			remove(NHKp);
			remove(RKp);
			remove(DH);
			remove(key);

			return;
		}

		string2Header(&Np, &PNp, DHRp, header);
		//store the message keys of the previous session
		stageSkippedMK(CKp, MK, obj->HKr, obj->Nr, PNp, obj->CKr);

		//try to decrypt the message with the updated key (computed with the DHR in the header)
		//the state will be updated only when the decryption is successful
		//otherwise all the computed keys will be dropped
		memmove(HKp, obj->NHKr, 32); //HKp = NHKr		

		crypto_scalarmult(DH, obj->DHRs_priv, DHRp); //DH(DHRs, DHRp)

		if(crypto_pwhash_scryptsalsa208sha256(key, 96, DH, 32, obj->RK, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0)
		{
			printf("Key derivation failed!\n");
			remove("tmp.txt");
			remove(msg1);
			remove(header);
			remove(msg2);
			remove(MK);
			remove(nonceH);
			remove(nonceM);
			remove(DHRp);
			remove(CKp);
			remove(CKpp);
			remove(HKp);
			remove(NHKp);
			remove(RKp);
			remove(DH);
			remove(key);

			return;
		}
		//derive the RKp, NHKp and CKpp
		memmove(RKp, key, 32);
		memmove(NHKp, key + 32, 32);
		memmove(CKpp, key + 64, 32);
		
		stageSkippedMK(CKp, MK, HKp, 0, Np, CKpp);

		memmove(nonceM, MK, NONCE_LENGTH);
		
		//if not successful, dropped all the values
		if (crypto_secretbox_open_easy(plaintext, msg2, len + MAC_LENGTH, nonceM, MK) == -1)
		{
			printf("Undecipherable message!\n");
			remove("tmp.txt");
			remove(msg1);
			remove(header);
			remove(msg2);
			remove(MK);
			remove(nonceH);
			remove(nonceM);
			remove(DHRp);
			remove(CKp);
			remove(CKpp);
			remove(HKp);
			remove(NHKp);
			remove(RKp);
			remove(DH);
			remove(key);

			return;
		}
	
		fprintf(fp, "Decrypted!\n");

		//otherwise, update the state
		memmove(obj->RK, RKp, 32);  //RK = RKp;
		memmove(obj->HKr, HKp, 32); //HKr = HKp
		memmove(obj->NHKr, NHKp, 32); //NHKr = NHKp
		memmove(obj->DHRr, DHRp, 32); //DHRr = DHRp
			
		obj->DHRs[0] = '\0';    //erase(DHRs)
		obj->DHRs_priv[0] = '\0';

		obj->ratchet_flag = true;
	}

	//write all the skipped keys in a cache file to the conversation file
	commitSkippedMK(obj->my_identity, obj->other_identity);

	obj->Nr = Np + 1;  //Nr = Np + 1
	
	memmove(obj->CKr, CKp, 32); //CKr = CKp
	
	remove(msg1);
	remove(header);
	remove(msg2);
	remove(MK);
	remove(nonceH);
	remove(nonceM);
	remove(DHRp);
	remove(CKp);
	remove(CKpp);
	remove(HKp);
	remove(NHKp);
	remove(RKp);
	remove(DH);
	remove(key);

	fclose(fp);

	return;
}

void header2String(int Ns, int PNs, unsigned char *DHRs, unsigned char *header)
{
	int i, r, q;
	 
	i = 9;
	q = Ns;
	do
	{
		r = q % 10;
		q = q / 10;
		header[i] = r + '0';
		i--;
	} while (q != 0);  //put the digits in the character array
	for (; i >= 0; i--)
		header[i] = '0';   //pad 0s in front

	i = 19;
	q = PNs;
	do
	{
		r = q % 10;
		q = q / 10;
		header[i] = r + '0';
		i--;
	} while (q != 0);  //put the digits in the character array
	for (; i >= 10; i--)
		header[i] = '0';   //pad 0s in front

	for (i = 20; i < 52; i++)
		header[i] = DHRs[i - 20];  //put the key in the array at last

	return;
}

void string2Header(int *Ns, int *PNs, unsigned char *DHRr, unsigned char *str)
{
	int i, t;

	t = 0;
	for (i = 0; i < 10; i++)
	{
		t *= 10;
		t += str[i] - '0';
	}  
	*Ns = t;  //transfer the digits charater to a integer

	t = 0;
	for (; i < 20; i++)
	{
		t *= 10;
		t += str[i] - '0';
	}
	*PNs = t;  //transfer the digits charater to a integer

	for (; i < 52; i++)
		DHRr[i - 20] = str[i];  //copy the last 32 bytes as the ratchet key

	return;
}

int trySkippedMK(unsigned char *decryption, char *msg1, unsigned char *msg2, int len, char *name1, char *name2)
{
	FILE *fp1, *fp2, *fp;
	char text[50];
	char c;
	int i, j;
	unsigned char HK[50], MK[50], nonceH[NONCE_LENGTH], nonceM[NONCE_LENGTH];
	unsigned char header[HEADER_LENGTH];
	int find = 0;

	for (i = 0, j = 0; name1[j] != '\0'; i++, j++)
		text[i] = name1[j];
	for (j = 0; name2[j] != '\0'; i++, j++)
		text[i] = name2[j];
	text[i++] = 'C';
	text[i++] = 'o';
	text[i++] = 'n';
	text[i++] = '.';
	text[i++] = 't';
	text[i++] = 'x';
	text[i++] = 't';
	text[i] = '\0';
	
	fp = fopen("log.txt", "a");
	fp1 = fopen(text, "r");
	fp2 = fopen("dup.txt", "w");
	if (fp1 == NULL || fp == NULL)  //no this file yet
	{
		fclose(fp2);
		fclose(fp);
		remove("dup.txt");
		remove(HK);
		remove(MK);
		remove(nonceH);
		remove(nonceM);
		remove(header);
		return 0;
	}
	c = fgetc(fp1);
	if (c == EOF)   //no content yet
	{
		fclose(fp1);
		fclose(fp2);
		remove("dup.txt");
		remove(HK);
		remove(MK);
		remove(nonceH);
		remove(nonceM);
		remove(header);
		return 0;
	}

	while (1)
	{
		i = 0;
		while (c != '#')  //read the header key
		{
			fscanf(fp1, "0x%2x", &HK[i]);
			i++;
			c = fgetc(fp1);
		}
		i = 0;
		while ((fgetc(fp1)) != '\n');

		while ((fgetc(fp1)) != '#') //read the message key
		{
			fscanf(fp1, "0x%2x", &MK[i]);
			i++;
		}
		i = 0;
		while ((fgetc(fp1)) != '\n');

		memmove(nonceH, HK, NONCE_LENGTH);
		memmove(nonceM, MK, NONCE_LENGTH);  //get the nonces
		
		if ((crypto_secretbox_open_easy(header, msg1, HEADER_LENGTH + MAC_LENGTH, nonceH, HK) == 0) &&
			(crypto_secretbox_open_easy(decryption, msg2, len + MAC_LENGTH, nonceM, MK) == 0))
		{
			fprintf(fp, "Correct key found in the stored keys, decrypted! Key deleted!\n");
			find = 1;
			break;    //find the matching key
		}
		
		for (i = 0; i < 32; ++i)  //duplicate the incorrect header key and message key to another file
		{
			fprintf(fp2, ",0x%02x", (unsigned int)HK[i]);
		}
		fprintf(fp2, "#header key\n");
		for (i = 0; i < 32; ++i)
		{
			fprintf(fp2, ",0x%02x", (unsigned int)MK[i]);
		}
		fprintf(fp2, "#message key\n");

		c = fgetc(fp1);
		if (c == EOF)
			break;
	}

	if(find == 1)
		c = fgetc(fp1);
	while (c != EOF)  //if exit becase of finding the matching key, the keys may not be copied completely
	{
		fputc(c, fp2);
		c = fgetc(fp1);
	}

	remove(HK);
	remove(MK);
	remove(nonceH);
	remove(nonceM);
	remove(header); 

	fclose(fp);
	fclose(fp1);
	fclose(fp2);

	remove(text);  //delete the old conversation file
	rename("dup.txt", text); //change the name of the cache file to that of the coversation file

	if (find)
		return 1;
	else return 0;
}

void stageSkippedMK(unsigned char *CKp, unsigned char *MK, unsigned char *HKr, int Nr, int Np, unsigned char *CKr)
{
	int i, j;
	FILE *fp, *fp0;
	fp0 = fopen("log.txt", "a");
	fp = fopen("tmp.txt", "a");
	if (fp == NULL || fp0 == NULL)
	{
		printf("Error in opening file!\n");
		return;
	}
	memmove(CKp, CKr, 32);
	
	for (i = Nr; i < Np; i++)
	{
		crypto_auth_hmacsha256(MK, CKp, 32, "0x00");
		crypto_auth_hmacsha256(CKp, CKp, 32, "0x01");
		fprintf(fp0, "Skipped message key computed!\n");
		for (j = 0; j < 32; ++j)
		{
			fprintf(fp, ",0x%02x", (unsigned int)HKr[j]);
		}
		fprintf(fp, "#header key\n");

		for (j = 0; j < 32; ++j)
		{
			fprintf(fp, ",0x%02x", (unsigned int)MK[j]);
		}
		fprintf(fp, "#message key\n");
	}

	crypto_auth_hmacsha256(MK, CKp, 32, "0x00"); //the message key for number Np, not stored in the file
	crypto_auth_hmacsha256(CKp, CKp, 32, "0x01");

	fclose(fp0);
	fclose(fp);
	return;
}

void commitSkippedMK(char *name1, char *name2)
{
	FILE *fp1, *fp2, *fp;
	char text[50];
	char c;
	int i, j;
	for (i = 0, j = 0; name1[j] != '\0'; i++, j++)
		text[i] = name1[j];
	for (j = 0; name2[j] != '\0'; i++, j++)
		text[i] = name2[j];
	text[i++] = 'C';
	text[i++] = 'o';
	text[i++] = 'n';
	text[i++] = '.';
	text[i++] = 't';
	text[i++] = 'x';
	text[i++] = 't';
	text[i] = '\0';

	fp = fopen("log.txt", "a");
	fp1 = fopen("tmp.txt", "r");
	fp2 = fopen(text, "a");
	if (fp1 == NULL || fp2 == NULL || fp == NULL)
	{
		printf("Error in opening file!\n");
		return;
	}

	c = fgetc(fp1);
	if(c != EOF)
	{
		while (1)
		{
			fputc(c, fp2);
			c = fgetc(fp1);
			if (c == EOF)
				break;
		}
		fprintf(fp, "All the computed message key(s) above committed!\n");
	}

	fclose(fp);
	fclose(fp1);
	fclose(fp2);

	if (remove("tmp.txt") != 0)
		printf("The cache file was not cleared!\n");

	return;
}
