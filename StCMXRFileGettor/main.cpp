#include "windows.h"
#include "stdio.h"
#include "DES.h"

short get2( const char* in ) // in���� 2byte�� �о short Ÿ������ ����
{
	char temp[2];
	memcpy( temp, in, 2 );

	temp[0] = in[1];
	temp[1] = in[0];

	short* ptemp = (short*) temp;
	return *ptemp;
}

int get4( const char* in ) // in���� 4byte�� �о int Ÿ������ ����
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

long long get8( const char* in ) // in���� 8byte�� �о long long Ÿ������ ����
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

int getIndex( const char* data ) // ��ȣ���� INDEX ���ϴ� ���
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

int writeToFile( const char* inFileName, const char* decData, int dataSize ) // ��� �����͸� ���Ϸ� ����
{
	// ��� ���� ����
	//
	char outFileName[256];
	memset( outFileName, 0, 256 );

	strncpy( outFileName, inFileName, strlen( inFileName )  );
	strcat( outFileName, ".dec" ); // ������ϸ� = �Է����ϸ� + .dec

	FILE* outFile;
	outFile = fopen( outFileName, "wb" );

	if( outFile == NULL ) // �̹� ������ �����Ѵٸ� ����
	{
		char removeCommand[ 5 ];
		memset( removeCommand, 0, sizeof(removeCommand) );
		strcpy( removeCommand, "del " );
		strcat( removeCommand, outFileName );
		system( removeCommand );
	}

	outFile = fopen( outFileName, "wb" ); // �ٽ� ����

	if( outFile == NULL ) // ������ �� ���� ������
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

	// �Է� XRIT ���� �б�
	//
	FILE* inFile = fopen( argv[1], "rb" );

	if( inFile == NULL )
	{
		puts( "Can not found XRIT data input file path" );
		return -2;
	}
	
	fseek( inFile, 0, SEEK_END ); // ���� ũ�� ���ϱ�
	long size = ftell( inFile );
	fseek( inFile, 0, SEEK_SET );
	
	char* allData = new char[ size ];
	fread( allData, size, 1, inFile ); // ���� �б�
	
	// ������ ���� �м� COMS HRIT/LRIT Mission Specification�� ����
	
	const int TOTAL_HEADER_LENGTH		= get4( allData + 4 );
	const long long DATA_FIELD_LENGTH	= get8( allData + 8 ); // bit ����
	const int DEC_INDEX					= getIndex( allData );

	char* dataPos = allData + TOTAL_HEADER_LENGTH; // data ������

	// �Է� decryptkeytable ����
	FILE* decFile = fopen( argv[2], "rb" );

	if( decFile == NULL )
	{
		puts( "Can not found decryption input file path" );
		return -2;
	}

	char* decData = new char[ 302 ]; // decryption key table ���� ũ��� 302����Ʈ�� ������.
	fread( decData, 302, 1, decFile ); // ���� �б�

	short itemcount = get2( decData );

	for( int i = 0 ; i < itemcount; i++ )
	{
		char* currPos = ( decData + 2 ) + 10 * i; // ���� ������
		
		int index		= get2( currPos ); // index���� ����.

		if( index == DEC_INDEX )
		{
			unsigned long long key	= get8( currPos + 2 ); // key ���� ����.
			
			DES des;
			des.setKey( key ); // ��ȣŰ �Է�
			
			dataPos = allData + TOTAL_HEADER_LENGTH; // data ������
			des.decrypt( ( unsigned char* ) dataPos, DATA_FIELD_LENGTH/8 ); // ��ȣ����

			char* flag = (char*) dataPos;
			const char jpeg1[2] = { 0xFF, 0xD8 }; // JPEG�� ���� �÷���
			const char jpeg2[2] = { 0xFF, 0xD9 }; // JPEG�� ���� �÷���

			bool bRet1 = flag[0] == jpeg1[0];
			bool bRet2 = flag[1] == jpeg1[1];
			bool bRet3 = flag[0] == jpeg2[0];
			bool bRet4 = flag[1] == jpeg2[1];

			if( ( bRet1 && bRet2 ) || ( bRet3 && bRet4 ) ) // JPEG�� ���� �÷��׸� ã�� �� ������ ��ȣ�� ���������� ������ ��.
			{
				puts( "Decryption Successful!");

				int nRet = writeToFile( argv[1], dataPos, DATA_FIELD_LENGTH/8 ); // ��ȣ�� ������ ������ �κи� ���Ϸ� ������.
				if( nRet  == 0 )
				{
					puts( "Done.");
				}
				else
				{
					puts( "Writing File Error!");
				}

				exit( nRet ); // ����
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
