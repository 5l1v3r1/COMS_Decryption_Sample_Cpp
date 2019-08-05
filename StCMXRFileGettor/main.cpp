#include "windows.h"
#include "stdio.h"
#include "DES.h"

short get2( const char* in ) // in에서 2byte를 읽어서 short 타입으로 리턴
{
	char temp[2];
	memcpy( temp, in, 2 );

	temp[0] = in[1];
	temp[1] = in[0];

	short* ptemp = (short*) temp;
	return *ptemp;
}

int get4( const char* in ) // in에서 4byte를 읽어서 int 타입으로 리턴
{
	char temp[4];
	memcpy( temp, in, 4 );

	temp[0] = in[3];
	temp[1] = in[2];
	temp[2] = in[1];
	temp[3] = in[0];

	int* ptemp = (int*) temp;
	return *ptemp;
}

long long get8( const char* in ) // in에서 8byte를 읽어서 long long 타입으로 리턴
{
	char temp[8];
	memcpy( temp, in, 8 );

	temp[0] = in[7];
	temp[1] = in[6];
	temp[2] = in[5];
	temp[3] = in[4];
	temp[4] = in[3];
	temp[5] = in[2];
	temp[6] = in[1];
	temp[7] = in[0];

	long long* ptemp = (long long*) temp;
	return *ptemp;
}

int getIndex( const char* data ) // 암호해제 INDEX 구하는 기능
{
	
	int temp;
	const char* pos = data;

	pos += 16; // primary header

	pos += 9; // Image Structer header
	pos += 3; // image navigation header
	pos += 48; // image naviation field
	pos += 1; // image data function
	
	int dataSize = get2( pos ); //image data function data length

	pos += 2;
	pos += ( dataSize - 3 );
	
	pos ++; // annotation text header
	dataSize = get2( pos ); // annotation text data length 
	pos += 2;
	pos += ( dataSize - 3 );

	pos += 10; // time stamp header
	pos += 3; // key header

	return get4( pos ); // key index

}

int writeToFile( const char* inFileName, const char* decData, int dataSize ) // 결과 데이터를 파일로 저장
{
	// 출력 파일 생성
	//
	char outFileName[256];
	memset( outFileName, 0, 256 );

	strncpy( outFileName, inFileName, strlen( inFileName )  );
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
		return -6;
	}

	if( 0 == fwrite( decData, dataSize, 1, outFile ) )
	{
		printf( "Decrypted Data File Name: %s\r\n", outFileName );
	}

	fclose( outFile );

	return 0;
}

int main(int argc, char *argv[])
{
	if( argc != 3 )
	{
		puts( "Usage:" );
		puts( "      StCMXRFileGettor servicedata(filePath) decryptKeyTable(filePath)" );
		return -1;
	}

	// 입력 XRIT 파일 읽기
	//
	FILE* inFile = fopen( argv[1], "rb" );

	if( inFile == NULL )
	{
		puts( "Can not found XRIT data input file path" );
		return -2;
	}
	
	fseek( inFile, 0, SEEK_END ); // 파일 크기 구하기
	long size = ftell( inFile );
	fseek( inFile, 0, SEEK_SET );
	
	char* allData = new char[ size ];
	fread( allData, size, 1, inFile ); // 파일 읽기
	
	// 데이터 구조 분석 COMS HRIT/LRIT Mission Specification에 따라
	
	const int TOTAL_HEADER_LENGTH		= get4( allData + 4 );
	const long long DATA_FIELD_LENGTH	= get8( allData + 8 ); // bit 단위
	const int DEC_INDEX					= getIndex( allData );

	char* dataPos = allData + TOTAL_HEADER_LENGTH; // data 포인터

	// 입력 decryptkeytable 읽음
	FILE* decFile = fopen( argv[2], "rb" );

	if( decFile == NULL )
	{
		puts( "Can not found decryption input file path" );
		return -2;
	}

	char* decData = new char[ 302 ]; // decryption key table 파일 크기는 302바이트로 고정됨.
	fread( decData, 302, 1, decFile ); // 파일 읽기

	short itemcount = get2( decData );

	for( int i = 0 ; i < itemcount; i++ )
	{
		char* currPos = ( decData + 2 ) + 10 * i; // 현재 포인터
		
		int index		= get2( currPos ); // index값을 구함.

		if( index == DEC_INDEX )
		{
			unsigned long long key	= get8( currPos + 2 ); // key 값을 구함.
			
			DES des;
			des.setKey( key ); // 암호키 입력
			
			dataPos = allData + TOTAL_HEADER_LENGTH; // data 포인터
			des.decrypt( ( unsigned char* ) dataPos, DATA_FIELD_LENGTH/8 ); // 암호해제

			char* flag = (char*) dataPos;
			const char jpeg1[2] = { 0xFF, 0xD8 }; // JPEG의 압축 플레그
			const char jpeg2[2] = { 0xFF, 0xD9 }; // JPEG의 압축 플레그

			bool bRet1 = flag[0] == jpeg1[0];
			bool bRet2 = flag[1] == jpeg1[1];
			bool bRet3 = flag[0] == jpeg2[0];
			bool bRet4 = flag[1] == jpeg2[1];

			if( ( bRet1 && bRet2 ) || ( bRet3 && bRet4 ) ) // JPEG의 압축 플레그를 찾을 수 있으면 암호가 정상적으로 해제된 것.
			{
				puts( "Decryption Successful!");

				int nRet = writeToFile( argv[1], dataPos, DATA_FIELD_LENGTH/8 ); // 암호가 해제된 데이터 부분만 파일로 저장함.
				if( nRet  == 0 )
				{
					puts( "Done.");
				}
				else
				{
					puts( "Writing File Error!");
				}

				exit( nRet ); // 종료
			}
			else
			{
				puts( "Decryption Failed!");
			}
		}
		
	}

	puts( "Can not found the coincident KEY INDEX");
	exit( -7 );
}
