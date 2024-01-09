#ifndef PROFINET_H
#define PROFINET_H
#include "stdint.h"
#include <QObject>
#include <QAbstractSocket>
typedef uint16_t word;
typedef unsigned char uchar;
class QHostAddress;




#pragma pack(1)
// Error Codes
// from 0x0001 up to 0x00FF are severe errors, the Client should be disconnected
// from 0x0100 are S7 Errors such as DB not found or address beyond the limit etc..
// For Arduino Due the error code is a 32 bit integer but this doesn't change the constants use.
#define errTCPConnectionFailed 0x0001
#define errTCPConnectionReset  0x0002
#define errTCPDataRecvTout     0x0003
#define errTCPDataSend         0x0004
#define errTCPDataRecv         0x0005
#define errISOConnectionFailed 0x0006
#define errISONegotiatingPDU   0x0007
#define errISOInvalidPDU       0x0008

#define errS7InvalidPDU        0x0100
#define errS7SendingPDU        0x0200
#define errS7DataRead          0x0300
#define errS7DataWrite         0x0400
#define errS7Function          0x0500

#define errBufferTooSmall      0x0600

// Connection Type
#define PG       0x01
#define OP       0x02
#define S7_Basic 0x03

// ISO and PDU related constants
#define ISOsize        7  // size of TPKT + COTP Header
#define isotcp       102  // ISOTCP Port
#define MinPduSize    16  // Minimum S7 valid telegram size
#define MaxPduSize   247  // Maximum S7 valid telegram size (we negotiate 240 bytes + ISOsize)
#define CC          0xD0  // Connection confirm
#define Shift         17  // We receive data 17 bytes above to align with PDU.DATA[]

// S7 ID Area (Area that we want to read/write)
#define S7AreaPE    0x81
#define S7AreaPA    0x82
#define S7AreaMK    0x83
#define S7AreaDB    0x84
#define S7AreaCT    0x1C
#define S7AreaTM    0x1D

// WordLength
#define S7WLBit     0x01
#define S7WLByte    0x02
#define S7WLWord    0x04
#define S7WLDWord   0x06
#define S7WLReal    0x08
#define S7WLCounter 0x1C
#define S7WLTimer   0x1D

#define TS_ResBit   0x03
#define TS_ResByte  0x04
#define TS_ResInt   0x05
#define TS_ResReal  0x07
#define TS_ResOctet 0x09

const uchar S7CpuStatusUnknown = 0x00;
const uchar S7CpuStatusRun     = 0x08;
const uchar S7CpuStatusStop    = 0x04;

#define RxOffset    18
#define size_RD     31
#define size_WR     35

//typedef uint16_t word;          // 16 bit unsigned integer

typedef int16_t integer;        // 16 bit signed integer
typedef unsigned long dword;    // 32 bit unsigned integer
typedef long dint;              // 32 bit signed integer

typedef char *pchar;
typedef word *pword;
typedef dword *pdword;
typedef integer *pinteger;
typedef dint *pdint;
typedef float *pfloat;

typedef union{
	struct {
        char H[size_WR];                      // PDU Header
        char DATA[MaxPduSize-size_WR+Shift];  // PDU Data
	};
    char RAW[MaxPduSize+Shift];
}TPDU;


#pragma pack()


class S7Helper
{
public:
    bool bitAt(void *Buffer, int ByteIndex, uchar BitIndex);
	bool bitAt(int ByteIndex, int BitIndex);
    uchar byteAt(void *Buffer, int index);
    uchar byteAt(int index);
	word wordAt(void *Buffer, int index);
	word wordAt(int index);
	dword dWordAt(void *Buffer, int index);
	dword dWordAt(int index);
	float floatAt(void *Buffer, int index);
	float floatAt(int index);
	integer integerAt(void *Buffer, int index);
	integer integerAt(int index);
	long dintAt(void *Buffer, int index);
	long dintAt(int index);
	// New 2.0
    void setBitAt(void *Buffer, int ByteIndex, int BitIndex, bool Value);
	void setBitAt(int ByteIndex, int BitIndex, bool Value);
    void setByteAt(void *Buffer, int index, uchar value);
    void setByteAt(int index, uchar value);
	void setIntAt(void *Buffer, int index, integer value);
	void setIntAt(int index, integer value);
	void setDIntAt(void *Buffer, int index, dint value);
	void setDIntAt(int index, dint value);
	void setWordAt(void *Buffer, int index, word value);
	void setWordAt(int index, word value);
	void setDWordAt(void *Buffer, int index, dword value);
	void setDWordAt(int index, word value);
	void setFloatAt(void *Buffer, int index, float value);
	void setFloatAt(int index, float value);
	char * stringAt(void *Buffer, int index);
	char * stringAt(int index);
	void setStringAt(void *Buffer, int index, char *value);
	void setStringAt(int index, char *value);
};
extern S7Helper S7;



class QTcpSocket;
class S7Client :QObject
{
        Q_OBJECT
private:
    uint8_t m_localTSAP_H;
    uint8_t m_localTSAP_LO;
    uint8_t m_remoteTSAP_HI;
    uint8_t m_remoteTSAP_LO;
    uint8_t m_lastPDUType;
    uint16_t m_connType;

    QHostAddress* m_ipAddress;

	// Since we can use either an EthernetClient or a WifiClient
	// we have to create the class as an ancestor and then resolve
	// the inherited into S7Client creator.
    QTcpSocket* m_tcpClient;

    int m_PDULength;    // PDU Length negotiated
    int isoPdusize();
    int waitForData(uint16_t size, uint16_t Timeout);
    int recvISOPacket(uint16_t *size);
    int recvPacket(char *buf, uint16_t size);
    int tCPConnect();
	int isoConnect();
	int negotiatePduLength();
	int setLastError(int Error);
public:
	// Output properties
    bool m_connected;   // true if the Client is connected
    int m_lastError;    // Last Operation error
	// Input properties
    uint16_t m_recvTimeout; // Receving timeour
	// Methods
	//S7Client();
	S7Client();
    S7Client(int media) : S7Client(){}; // Compatibility V1.X
	~S7Client();
	// Basic functions
    void setConnectionParams(QHostAddress* address, uint16_t LocalTSAP, uint16_t RemoteTSAP);
	void setConnectionType(uint16_t ConnectionType);
    int connectTo(QHostAddress* address, uint16_t Rack, uint16_t Slot);
    int connect();
	void disconnect();
	int readArea(int Area, uint16_t DBNumber, uint16_t Start, uint16_t Amount, void *ptrData);
	int readArea(int Area, uint16_t DBNumber, uint16_t Start, uint16_t Amount, int WordLen, void *ptrData);
	int readBit(int Area, uint16_t DBNumber, uint16_t BitStart, bool &Bit);
	int writeArea(int Area, uint16_t DBNumber, uint16_t Start, uint16_t Amount, void *ptrData);
	int writeArea(int Area, uint16_t DBNumber, uint16_t Start, uint16_t Amount, int WordLen, void *ptrData);
	int writeBit(int Area, uint16_t DBNumber, uint16_t BitIndex, bool Bit);
	int writeBit(int Area, uint16_t DBNumber, uint16_t ByteIndex, uint16_t BitInByte, bool Bit);

    int GetPDULength(){ return m_PDULength; }
	// Extended functions
    int getDBSize(uint16_t DBNumber, uint16_t *size);
    int dBGet(uint16_t DBNumber, void *ptrData, uint16_t *size);
    int plcStart(); // Warm start
    int plcStop();
    int getPlcStatus(int *Status);
    int isoExchangeBuffer(uint16_t *size);
public slots:
    void displayError(QAbstractSocket::SocketError socketError);
};

extern TPDU PDU;

#endif // PROFINET_H
