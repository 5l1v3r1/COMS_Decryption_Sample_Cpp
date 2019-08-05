#include "windows.h"
#include "stdio.h"
#include "DES.h"

const int HEADER_SIZE		= 8;
const int KEY_ITEM_SIZE		= 16;
const int DES_KEY_SIZE		= 8;
const int KEY_INDEX_SIZE	= 2;
const int CRC_CHECKSUM_SIZE = 2;
const int ITEM_COUNT		= 30;
const int MAC_STRING_SIZE	= 12;
const int DATA_BLOCK_SIZE	= (KEY_ITEM_SIZE+KEY_INDEX_SIZE)*ITEM_COUNT;

struct keyset
{
	int					index;
	unsigned long long	key;
};

int printMessage( int id )
{
	if( id == -1 ) printf( "EncKeyMsgDecryptor.exe INPUT_FILE_PATH DECYRPT_KEY \r\n     ex: EncKeyMsgDecryptor.exe c:/EncyptionKeyMessage_001F2904C905.bin 001F2904C905" );
	if( id == -2 ) printf( "Can not found input file path.");
	if( id == -3 ) printf( "Input data size must be 550 byte.");
	if( id == -4 ) printf( "Invalid input key.");
	if( id == -5 ) printf( "Done.");
	if( id == -6 ) printf( "Output file exists already.");

	if( id == 1  ) printf( "Decryption key is not correct.");

	return id;
}

char ascTobinary( char code )
{
	if( code == '0' ) return 0x00;
	if( code == '1' ) return 0x01;
	if( code == '2' ) return 0x02;
	if( code == '3' ) return 0x03;
	if( code == '4' ) return 0x04;
	if( code == '5' ) return 0x05;
	if( code == '6' ) return 0x06;
	if( code == '7' ) return 0x07;
	if( code == '8' ) return 0x08;
	if( code == '9' ) return 0x09;

	if( code == 'a' ) return 0x0A;
	if( code == 'b' ) return 0x0B;
	if( code == 'c' ) return 0x0C;
	if( code == 'd' ) return 0x0D;
	if( code == 'e' ) return 0x0E;
	if( code == 'f' ) return 0x0F;

	if( code == 'A' ) return 0x0A;
	if( code == 'B' ) return 0x0B;
	if( code == 'C' ) return 0x0C;
	if( code == 'D' ) return 0x0D;
	if( code == 'E' ) return 0x0E;
	if( code == 'F' ) return 0x0F;

	return -1;
}

bool macAddressToHex( char* hexString, unsigned __int64& dst ) // hexString 문자열을 입력받아서 dst변수로 헥사값을 출력
{
	if( strlen( hexString ) != MAC_STRING_SIZE ) return false;

	dst = 0;
	char* pDst = ( char*)&dst;

	for( int i = 0 ; i < 6; i++ )
	{
		char bit04 = ascTobinary( hexString[i*2] );
		char bit58 = ascTobinary( hexString[i*2+1] );

		if( bit04 == -1 || bit58 == -1 )
			return false;

		char buf = 0;

		buf = ( bit04 & 0x0f ) << 4;
		buf = ( buf | ( bit58 & 0x0f ) );
		pDst[i] = buf;
	}

	return true;
}

int main(int argc, char *argv[])
{
	if( argc != 3 )
	{
		return printMessage( -1 );
	}

	// 입력 파일 읽기
	//
	FILE* inFile = fopen( argv[1], "rb" );

	if( inFile == NULL )
		return printMessage( -2 );

	char encData[550]; // 입력 파일 크기는 550 byte로 고정
	fread( encData, sizeof( encData ), 1, inFile ); // 파일 전체를 읽음
	fclose( inFile );

	char* header	= encData; // 헤더 포인터
	char* data		= encData + HEADER_SIZE; // 데이터 포인터
	char* crc		= encData + HEADER_SIZE + KEY_ITEM_SIZE* ITEM_COUNT; // crc 포인터

	// 입력 키 확인
	//
	char strkey[MAC_STRING_SIZE+1];
	memset( &strkey, 0, MAC_STRING_SIZE+1 );
	memcpy( strkey, argv[2], MAC_STRING_SIZE ); // 입력키 설정

	if( strlen(argv[2]) < MAC_STRING_SIZE )
		return printMessage( -4 );
	
	unsigned __int64 tempKey;

	if( macAddressToHex( strkey, tempKey ) == false )
	{
		return printMessage( -4 );
	}
	
	unsigned __int64* pKey = new unsigned __int64;
	
	((char*) pKey)[0] = ((char*) &tempKey)[7]; // endian 변환
	((char*) pKey)[1] = ((char*) &tempKey)[6];
	((char*) pKey)[2] = ((char*) &tempKey)[5];
	((char*) pKey)[3] = ((char*) &tempKey)[4];
	((char*) pKey)[4] = ((char*) &tempKey)[3];
	((char*) pKey)[5] = ((char*) &tempKey)[2];
	((char*) pKey)[6] = ((char*) &tempKey)[1];
	((char*) pKey)[7] = ((char*) &tempKey)[0];

	// 출력 파일 생성
	//
	char outFileName[256];
	memset( outFileName, 0, 256 );
	
	strncpy( outFileName, argv[1], strlen( argv[1])  );
	strcat( outFileName, ".dec" ); // 출력파일명 = 입력파일명 + .dec

	FILE* outFile;
	outFile = fopen( outFileName, "wb" );

	if( outFile == NULL ) // 이미 파일이 존재한다면 삭제
	{
		char removeCommand[ 5 ];
		memset( removeCommand, 0, sizeof(removeCommand) );
		strcpy( removeCommand, "del " );
		strcat( removeCommand, outFileName );
		system( removeCommand );
	}

	outFile = fopen( outFileName, "wb" ); // 다시 생성
	
	if( outFile == NULL ) // 제거할 수 없는 파일임
	{
		return printMessage( -6 );
	}

	short itemcount = ITEM_COUNT;
	
	fwrite( ((char*)&itemcount + 1), sizeof( char ), 1, outFile ); 
	fwrite( ((char*)&itemcount), sizeof( char ), 1, outFile ); //endian 변환

	// 암호 키 설정
	//
	DES des;

	des.setKey( *pKey ); // 암호키 입력

	for( int i = 0 ; i < ITEM_COUNT; i++ )
	{
		// 암호 해제 
		// 
		unsigned char* pDataPos = ( unsigned char* ) ( data + ( KEY_INDEX_SIZE + KEY_ITEM_SIZE ) * i ); // 다음 데이터 위치: 18byte의 포인터
		unsigned char* pKeyPos	= pDataPos + KEY_INDEX_SIZE; // 다음 암호키 위치: 16byte의 포인터
		des.decrypt( pDataPos + KEY_INDEX_SIZE, KEY_ITEM_SIZE ); // 암호해제, 16byte만
		fwrite( pDataPos, KEY_INDEX_SIZE + DES_KEY_SIZE, 1, outFile ); // 파일에 index 및 암호해제 데이터 8byte 저장

		if( pKeyPos[8] != 0x08 || 
			pKeyPos[9] != 0x08 || 
			pKeyPos[10] != 0x08 ||
			pKeyPos[11] != 0x08 || 
			pKeyPos[12] != 0x08 || 
			pKeyPos[13] != 0x08 ||
			pKeyPos[14] != 0x08 ||
			pKeyPos[15] != 0x08 )
			return printMessage( 1 );
	}
	
	fclose( outFile );

	printf( "Output File Path: %s\r\n", outFileName );
	printf( "Done.\r\n");

	return 0;
}
