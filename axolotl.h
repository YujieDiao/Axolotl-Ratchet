#ifndef AXOLOTL_H
#define AXOLOTL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "/usr/local/include/sodium.h"

#define HEADER_LENGTH 52   //the length of header in the message
#define NONCE_LENGTH 24   //the length of the nonce using crypto_secretbox_easy
                           //the nonce is the first 24 bytes of the key
#define MAC_LENGTH 16      //the length of the mac tag using crypto_secretbox_easy

typedef struct {
	char *name;  //name of the user
	unsigned char seed[32];  //phrase key
	unsigned char public_key[32];
	unsigned char secret_key[32];
} User; 

typedef struct {
	unsigned char public_key[32];
	unsigned char secret_key[32];
} EphemeralKey; 

typedef struct {
	char *my_identity;   //the name of the send side
	char *other_identity;  //the name of the receive side
	unsigned char RK[32];  //root key
	unsigned char HKs[32];  //header key, the send side
	unsigned char HKr[32];  //header key, the receive side
	unsigned char NHKs[32]; //next header key, the send side
	unsigned char NHKr[32]; //header key, the receive side
	unsigned char CKs[32];   //chain key, the send side
	unsigned char CKr[32];  //chain key, the receive side
	unsigned char DHIs_priv[32]; //the private key of the send side
	unsigned char DHIs[32];  //the identity key of the send side 
	unsigned char DHIr[32];  //the identity key of the receive side
	unsigned char DHRs_priv[32]; //the secret to ratchet key of the send side
	unsigned char DHRs[32];  //the ratchet key of the send side
	unsigned char DHRr[32];   //the ratchet key of the receive side
	int Ns, Nr; //message numbers of the send and receive side
	int PNs;  //number of messages sent under the previous ratchet
	bool ratchet_flag;  //generate a new ratchet key if it's true
	int mode; //1 as the receive side, 0 as the start side
} Axolotl;

int char2Hex(unsigned char *seed, char *phrase_key); //transfer the phrase key in charaters to hex seed
User *new_user(char* name);  //generate a user
void print_user(User *user);
void addNewUser(); //generate a key pair based on the user input, and save it to the file users.txt
void queryUser();  //query the public key of some name from users.txt

void axolotl(char *name, Axolotl *obj);  //initialize an empty axolotl state
                                         //the name and identity key are put into the state after the user
                                         //inputs name and phrase key
void initState(Axolotl *obj, char *name, unsigned char *B, unsigned char *a0, unsigned char *B0, unsigned char *DHR);  
                                       //compute all the keys when handshake key and ratchet key of the other side are given
                                       //obj is the axolotl state after initializing with axolotl()
                                       //name is the name of the other side
									   //B is the identity key of the other side
									   //a0 is the secret of the handshake key of this side
									   //B0 is the public of the handshake key of the other side
									   //DHR is the other's ratchet key
EphemeralKey *generateEphemeralKey(); //generate a random key pair
unsigned char *keyAgreement(int mode, unsigned char *a, unsigned char *a0, unsigned char *B, unsigned char *B0);
   //compute the shared master key by one's secrets of handshake key and identity key and the other's public of handshake
   //key and identity key
void getFilename(char *text, char *name1, char *name2);
   //the axolotl state of name1 to name2 is saved in a file named after the names of the two sides
   //text = name1 + name2 + ".txt"
int verify(char *name, unsigned char *identity_key);
   //check if the given user is in the users.txt file and if the name matches the identity key
void saveState(Axolotl *obj);
   //save the state to the named file, the identity key pair will not be saved
void loadState(Axolotl *obj, char *name);
   //load the state from the saved file by giving two sides' names
   //phrase key of name is needed to put the public and secret of the identity key back to the state
void encrypt(Axolotl *obj, unsigned char *ciphertext, unsigned char *plaintext, int len);
   //encrypt the plaintext with crypto_secrectbox_easy, and put it in ciphertext
   //len is the length of the plaintext
void decrypt(Axolotl *obj, unsigned char *ciphertext, unsigned char *plaintext, int len);
   //decrypt the ciphertext with crypto_secrectbox_open_easy, and put it in plaintext
   //len is the length of the plaintext, which should be given in the transmitted message 
void header2String(int Ns, int PNs, unsigned char *DHRs, unsigned char *header);
   //transfer the header information to a 52-byte string, 10 bytes for Ns, 10 bytes for PNs, 32 bytes for DHRs
void string2Header(int *Ns, int *PNs, unsigned char *DHRr, unsigned char *str);
   //get Ns, PNs, and DHRr from the decrypted header 
int trySkippedMK(unsigned char *decryption, char *msg1, unsigned char *msg2, int len, char *name1, char *name2);
   //try the skipped message keys in the file, if decryption succeeds, delete this key, return 1, else 0
   //name1 is recipient's name, name2 is the sender's name
   //msg1 is the encryption of header, msg2 is the encryption of message, len is the length of msg2
   //the decryption stores the decryption of msg2
void stageSkippedMK(unsigned char *CKp, unsigned char *MK, unsigned char *HKr, int Nr, int Np, unsigned char *CKr);
   //compare the received message number Np to the Nr in the state, compute and store all the message keys
   //between number Nr and Np. For all these message keys the same header key HKr from the state is applied.
   //CKr is the chain key at the message number Nr
   //the computed chain key and message key for message number Np will be put in CKp and MK
void commitSkippedMK(char *name1, char *name2);
   //the skipped keys are stored in another file "tmp.txt", when decipher succeeds, this function will copy the computed skipped
   //keys to the conversation file name1 + name2 + "Con.txt", and delete "tmp.txt"

#endif
