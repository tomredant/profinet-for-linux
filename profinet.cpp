#include "profinet.h"
#include <QThread>
#include <QDateTime>
#include <QTcpSocket>
#include <QHostAddress>

// ISO Connection Request telegram (contains also ISO Header and COTP Header)
uchar ISO_CR[] = {
    // TPKT (RFC1006 Header)
    0x03, // RFC 1006 ID (3)
    0x00, // Reserved, always 0
    0x00, // High part of packet lenght (entire frame, payload and TPDU included)
    0x16, // Low part of packet lenght (entire frame, payload and TPDU included)
    // COTP (ISO 8073 Header)
    0x11, // PDU size Length
    0xE0, // CR - Connection Request ID
    0x00, // Dst Reference HI
    0x00, // Dst Reference LO
    0x00, // Src Reference HI
    0x01, // Src Reference LO
    0x00, // Class + Options Flags
    0xC0, // PDU Max Length ID
    0x01, // PDU Max Length HI
    0x0A, // PDU Max Length LO
    0xC1, // Src TSAP Identifier
    0x02, // Src TSAP Length (2 bytes)
    0x01, // Src TSAP HI (will be overwritten by ISOConnect())
    0x00, // Src TSAP LO (will be overwritten by ISOConnect())
    0xC2, // Dst TSAP Identifier
    0x02, // Dst TSAP Length (2 bytes)
    0x01, // Dst TSAP HI (will be overwritten by ISOConnect())
    0x02  // Dst TSAP LO (will be overwritten by ISOConnect())
};

// S7 PDU Negotiation Telegram (contains also ISO Header and COTP Header)
uchar S7_PN[] = {
    0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, // TPKT + COTP (see above for info)
    0x32, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x08, 0x00,
    0x00, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0xf0 // PDU Length Requested = HI-LO 240 bytes
};

// S7 Read/Write Request Header (contains also ISO Header and COTP Header)
uchar S7_RW[] = { // 31-35 bytes
                  0x03, 0x00,
                  0x00, 0x1f, // Telegram Length (Data size + 31 or 35)
                  0x02, 0xf0, 0x80, // COTP (see above for info)
                  0x32,       // S7 Protocol ID
                  0x01,       // Job Type
                  0x00, 0x00, // Redundancy identification
                  0x05, 0x00, // PDU Reference
                  0x00, 0x0e, // Parameters Length
                  0x00, 0x00, // Data Length = size(bytes) + 4
                  0x04,       // Function 4 Read Var, 5 Write Var
                  0x01,       // Items count
                  0x12,       // Var spec.
                  0x0a,       // Length of remaining bytes
                  0x10,       // Syntax ID
                  S7WLByte,   // Transport size (default, could be changed)
                  0x00,0x00,  // Num Elements
                  0x00,0x00,  // DB Number (if any, else 0)
                  0x84,       // Area Type
                  0x00, 0x00, 0x00, // Area Offset
                  // WR area
                  0x00,       // Reserved
                  0x04,       // Transport size
                  0x00, 0x00, // Data Length * 8 (if not timer or counter)
                };


// S7 Get Block Info Request Header (contains also ISO Header and COTP Header)
uchar S7_BI[] = {
    0x03, 0x00, 0x00, 0x25, 0x02, 0xf0, 0x80, 0x32,
    0x07, 0x00, 0x00, 0x05, 0x00, 0x00, 0x08, 0x00,
    0x0c, 0x00, 0x01, 0x12, 0x04, 0x11, 0x43, 0x03,
    0x00, 0xff, 0x09, 0x00, 0x08, 0x30, 0x41,
    0x30, 0x30, 0x30, 0x30, 0x30, // ASCII DB Number
    0x41
};

// S7 Put PLC in STOP state Request Header (contains also ISO Header and COTP Header)
uchar S7_STOP[] = {
    0x03, 0x00, 0x00, 0x21, 0x02, 0xf0, 0x80, 0x32,
    0x01, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
    0x50, 0x5f, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41,
    0x4d
};

// S7 Put PLC in RUN state Request Header (contains also ISO Header and COTP Header)
uchar S7_START[] = {
    0x03, 0x00, 0x00, 0x25, 0x02, 0xf0, 0x80, 0x32,
    0x01, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x14, 0x00,
    0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xfd, 0x00, 0x00, 0x09, 0x50, 0x5f, 0x50, 0x52,
    0x4f, 0x47, 0x52, 0x41, 0x4d
};

// S7 Get PLC Status Request Header (contains also ISO Header and COTP Header)
uchar S7_PLCGETS[] = {
    0x03, 0x00, 0x00, 0x21, 0x02, 0xf0, 0x80, 0x32,
    0x07, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x08, 0x00,
    0x08, 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01,
    0x00, 0xff, 0x09, 0x00, 0x04, 0x04, 0x24, 0x00,
    0x00
};


TPDU PDU;


S7Helper S7;

bool S7Helper::bitAt(void *Buffer, int ByteIndex, uchar BitIndex)
{
    uchar mask[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    pchar Pointer = pchar(Buffer) + ByteIndex;

    if (BitIndex>7)
        return false;
    else
        return (*Pointer & mask[BitIndex]);
}

bool S7Helper::bitAt(int ByteIndex, int BitIndex)
{
    return bitAt(&PDU.DATA[0], ByteIndex, BitIndex);
}

uchar S7Helper::byteAt(void *Buffer, int index)
{
    pchar Pointer = pchar(Buffer) + index;
    return *Pointer;
}
uchar S7Helper::byteAt(int index)
{
    return byteAt(&PDU.DATA, index);
}
word S7Helper::wordAt(void *Buffer, int index)
{
    word hi=(*(pchar(Buffer) + index))<<8;
    return hi+*(pchar(Buffer) + index+1);
}
word S7Helper::wordAt(int index)
{
    return wordAt(&PDU.DATA, index);
}
dword S7Helper::dWordAt(void *Buffer, int index)
{
    pchar pb;
    dword dw1;

    pb=pchar(Buffer) + index;
    dw1=*pb;dw1<<=8;
    pb=pchar(Buffer) + index + 1;
    dw1+=*pb;dw1<<=8;
    pb=pchar(Buffer) + index + 2;
    dw1+=*pb;dw1<<=8;
    pb=pchar(Buffer) + index + 3;
    dw1+=*pb;
    return dw1;
}

dword S7Helper::dWordAt(int index)
{
    return dWordAt(&PDU.DATA, index);
}
float S7Helper::floatAt(void *Buffer, int index)
{
    dword dw = dWordAt(Buffer, index);
    return *(pfloat(&dw));
}
float S7Helper::floatAt(int index)
{
    return floatAt(&PDU.DATA, index);
}
integer S7Helper::integerAt(void *Buffer, int index)
{
    word w = wordAt(Buffer, index);
    return *(pinteger(&w));
}
integer S7Helper::integerAt(int index)
{
    return integerAt(&PDU.DATA, index);
}
long S7Helper::dintAt(void *Buffer, int index)
{
    dword dw = dWordAt(Buffer, index);
    return *(pdint(&dw));
}
long S7Helper::dintAt(int index)
{
    return dintAt(&PDU.DATA, index);
}
void S7Helper::setBitAt(void *Buffer, int ByteIndex, int BitIndex, bool Value)
{
    uchar Mask[] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80};
    pchar Pointer = pchar(Buffer) + ByteIndex;
    if (BitIndex < 0) BitIndex = 0;
    if (BitIndex > 7) BitIndex = 7;

    if (Value)
        *Pointer=*Pointer | Mask[BitIndex];
    else
        *Pointer=*Pointer & ~Mask[BitIndex];
}
void S7Helper::setBitAt(int ByteIndex, int BitIndex, bool Value)
{
    setBitAt(&PDU.DATA, ByteIndex, BitIndex, Value);
}
void S7Helper::setByteAt(void *Buffer, int index, uchar value)
{
    *(pchar(Buffer)+index)=value;
}
void S7Helper::setByteAt(int index, uchar value)
{
    PDU.DATA[index]=value;
}

void S7Helper::setIntAt(void *Buffer, int index, integer value)
{
    *(pchar(Buffer)+index)  =uchar(value>>8);
    *(pchar(Buffer)+index+1)=uchar(value & 0x00FF);
}

void S7Helper::setIntAt(int index, integer value)
{
    setIntAt(&PDU.DATA, index, value);
}

void S7Helper::setDIntAt(void *Buffer, int index, dint value)
{
    *(pchar(Buffer)+index)  =uchar((value >> 24) & 0xFF);
    *(pchar(Buffer)+index+1)=uchar((value >> 16) & 0xFF);
    *(pchar(Buffer)+index+2)=uchar((value >> 8) & 0xFF);
    *(pchar(Buffer)+index+3)=uchar(value & 0x00FF);
}
void S7Helper::setDIntAt(int index, dint value)
{
    setDIntAt(&PDU.DATA, index, value);
}

void S7Helper::setWordAt(void *Buffer, int index, word value)
{
    *(pchar(Buffer)+index)  =uchar(value>>8);
    *(pchar(Buffer)+index+1)=uchar(value & 0x00FF);
}

void S7Helper::setWordAt(int index, word value)
{
    setWordAt(&PDU.DATA, index, value);
}

void S7Helper::setDWordAt(void *Buffer, int index, dword value)
{
    *(pchar(Buffer)+index)  =uchar((value >> 24) & 0xFF);
    *(pchar(Buffer)+index+1)=uchar((value >> 16) & 0xFF);
    *(pchar(Buffer)+index+2)=uchar((value >> 8) & 0xFF);
    *(pchar(Buffer)+index+3)=uchar(value & 0x00FF);
}

void S7Helper::setDWordAt(int index, word value)
{
    setDWordAt(&PDU.DATA, index, value);
}

void S7Helper::setFloatAt(void *Buffer, int index, float value)
{
    pdword dvalue = pdword(&value);

    *(pchar(Buffer)+index)  =uchar((*dvalue >> 24) & 0xFF);
    *(pchar(Buffer)+index+1)=uchar((*dvalue >> 16) & 0xFF);
    *(pchar(Buffer)+index+2)=uchar((*dvalue >> 8) & 0xFF);
    *(pchar(Buffer)+index+3)=uchar(*dvalue & 0x00FF);
}

void S7Helper::setFloatAt(int index, float value)
{
    setFloatAt(&PDU.DATA, index, value);
}

char * S7Helper::stringAt(void *buffer, int index)
{
    return &pchar(buffer)[index];
}

char * S7Helper::stringAt(int index)
{
    return pchar(&PDU.DATA[index]);
}

void S7Helper::setStringAt(void *buffer, int index, char *value)
{
    strcpy(&pchar(buffer)[index],value);
}

void S7Helper::setStringAt(int index, char *value)
{
    strcpy(pchar(&PDU.DATA[index]),value);
}



S7Client::S7Client()
{
    // Default TSAP values for connectiong as PG to a S7300 (Rack 0, Slot 2)
    m_localTSAP_H = 0x01;
    m_localTSAP_LO = 0x00;
    m_remoteTSAP_HI= 0x01;
    m_remoteTSAP_LO= 0x02;
    m_connType = PG;
    m_connected = false;
    m_lastError = 0;
    m_PDULength = 0;
    m_recvTimeout = 500; // 500 ms
    m_tcpClient = new QTcpSocket();
}

S7Client::~S7Client()
{
    disconnect();
    delete m_tcpClient;
}

int S7Client::setLastError(int Error)
{
    m_lastError=Error;
    return Error;
}

int S7Client::waitForData(uint16_t size, uint16_t timeout)
{
    unsigned long elapsed = QDateTime::currentMSecsSinceEpoch();
    uint16_t bytesReady;

    do
    {
        // I don't like next function because imho is buggy, it returns 0 also if _sock==MAX_SOCK_NUM
        // but it belongs to the standard Ethernet library and there are too many dependencies to skip them.
        // So be very carefully with the munber of the clients, they must be <=4.
        bytesReady=m_tcpClient->bytesAvailable();
        if (bytesReady<size)
            QThread::usleep(500);
        else
            return setLastError(0);

        // Check for rollover - should happen every 52 days without turning off Arduino.
        if (QDateTime::currentMSecsSinceEpoch() <elapsed)
            elapsed=QDateTime::currentMSecsSinceEpoch() ; // Resets the counter, in the worst case we will wait some additional millisecs.

    }while(QDateTime::currentMSecsSinceEpoch() -elapsed<timeout);

    // Here we are in timeout zone, if there's something into the buffer, it must be discarded.
    if (bytesReady>0)
        m_tcpClient->flush();
//    else
//    {
//        if (!m_tcpClient->connected())
//            return setLastError(errTCPConnectionReset);
//    }

    return setLastError(errTCPDataRecvTout);
}

int S7Client::isoPdusize()
{
    uint16_t size = PDU.H[2];
    return (size<<8) + PDU.H[3];
}

int S7Client::recvPacket(char *buf, uint16_t size)
{
    waitForData(size,m_recvTimeout);
    if (m_lastError!=0)
        return m_lastError;
    if (m_tcpClient->read(buf, size)==0)
        return setLastError(errTCPConnectionReset);
    return setLastError(0);
}

void S7Client::setConnectionParams(QHostAddress* address, uint16_t LocalTSAP, uint16_t RemoteTSAP)
{
    m_ipAddress = address;
    m_localTSAP_H = LocalTSAP>>8;
    m_localTSAP_LO = LocalTSAP & 0x00FF;
    m_remoteTSAP_HI = RemoteTSAP>>8;
    m_remoteTSAP_LO = RemoteTSAP & 0x00FF;
}

void S7Client::setConnectionType(uint16_t ConnectionType)
{
    m_connType = ConnectionType;
}

int S7Client::connectTo(QHostAddress* address, uint16_t Rack, uint16_t Slot)
{
    setConnectionParams(address, 0x0100, (m_connType<<8)+(Rack * 0x20) + Slot);
    return connect();
}

int S7Client::connect()
{
    m_lastError = 0;
    if (!m_connected)
    {
        tCPConnect();
        if (m_lastError==0) // First stage : TCP Connection
        {
            isoConnect();
            if (m_lastError==0) // Second stage : ISOTCP (ISO 8073) Connection
            {
                m_lastError=negotiatePduLength(); // Third stage : S7 PDU negotiation
            }
        }
    }
    m_connected=m_lastError==0;
    return m_lastError;
}

void S7Client::disconnect()
{
    if (m_connected)
    {
        m_tcpClient->disconnect();
        m_connected = false;
        m_PDULength = 0;
        m_lastError = 0;
    }
}



void S7Client::displayError(QAbstractSocket::SocketError socketError)
{
    switch (socketError) {
    case QAbstractSocket::RemoteHostClosedError:
        break;
    case QAbstractSocket::HostNotFoundError:
        qDebug() << "host not found";
        break;
    case QAbstractSocket::ConnectionRefusedError:
        qDebug() << "connection refused";

        break;
    default:
        qDebug() << "the following error occured" << m_tcpClient->errorString();
    }
}



int S7Client::tCPConnect()
{
    m_tcpClient->connectToHost(m_ipAddress->toString(), (quint16) isotcp);
    return 0;
}

int S7Client::recvISOPacket(uint16_t *size)
{
    bool Done = false;
    pchar Target = pchar(&PDU.H[0])+Shift;
    m_lastError=0;

    while ((m_lastError==0) && !Done)
    {
        // Get TPKT (4 bytes)
        recvPacket(PDU.H, 4);
        if (m_lastError==0)
        {
            *size = isoPdusize();
            // Check 0 bytes Data Packet (only TPKT+COTP - 7 bytes)
            if (*size==7)
                recvPacket(PDU.H, 3); // Skip remaining 3 bytes and Done is still false
            else
            {
                if ((*size>MaxPduSize) || (*size<MinPduSize))
                    m_lastError=errISOInvalidPDU;
                else
                    Done = true; // a valid Length !=7 && >16 && <247
            }
        }
    }
    if (m_lastError==0)
    {
        recvPacket(PDU.H, 3); // Skip remaining 3 COTP bytes
        m_lastPDUType=PDU.H[1]; // Stores PDU Type, we need it
        *size-=ISOsize;
        // We need to align with PDU.DATA
        recvPacket(Target, *size);
    }
    if (m_lastError!=0)
        m_tcpClient->flush();
    return m_lastError;
}

int S7Client::isoConnect()
{
    bool Done = false;
    uint16_t Length;
    // Setup TSAPs
    ISO_CR[16]=m_localTSAP_H;
    ISO_CR[17]=m_localTSAP_LO;
    ISO_CR[20]=m_remoteTSAP_HI;
    ISO_CR[21]=m_remoteTSAP_LO;

    char* isoCRConverted = new char[sizeof(ISO_CR)];
    memcpy(isoCRConverted, &ISO_CR[0], sizeof(ISO_CR));
    if (m_tcpClient->write(isoCRConverted, sizeof(ISO_CR))==sizeof(ISO_CR))
    {
        delete[] isoCRConverted;
        recvISOPacket(&Length);
        if ((m_lastError==0) && (Length==15)) // 15 = 22 (sizeof CC telegram) - 7 (sizeof Header)
        {
            if (m_lastPDUType==CC) // Connection confirm
                return 0;
            else
                return setLastError(errISOInvalidPDU);
        }
        else
            return m_lastError;
    }
    else {
        delete[] isoCRConverted;
        return setLastError(errISOConnectionFailed);
    }
}

int S7Client::negotiatePduLength()
{
    uint16_t Length;

    char* s7PNConverted = new char[sizeof(S7_PN)];
    memcpy(s7PNConverted, &S7_PN[0], sizeof(S7_PN));
    if (m_tcpClient->write(s7PNConverted, sizeof(S7_PN))==sizeof(S7_PN))
    {
        delete[] s7PNConverted;
        recvISOPacket(&Length);
        if (m_lastError==0)
        {
            // check S7 Error
            if ((Length==20) && (PDU.H[27]==0) && (PDU.H[28]==0))  // 20 = size of Negotiate Answer
            {
                m_PDULength = PDU.RAW[35];
                m_PDULength = (m_PDULength<<8) + PDU.RAW[36]; // Value negotiated
                if (m_PDULength>0)
                    return 0;
                else
                    return setLastError(errISONegotiatingPDU);
            }
            else
                return setLastError(errISONegotiatingPDU);
        }
        else
            return m_lastError;
    }
    else {
        delete[] s7PNConverted;
        return setLastError(errISONegotiatingPDU);
    }
}

int S7Client::readArea(int Area, uint16_t dBNumber, uint16_t Start, uint16_t Amount, int WordLen, void *ptrData)
{
    unsigned long Address;
    unsigned long LongStart=Start;
    uint16_t NumElements;
    uint16_t MaxElements;
    uint16_t TotElements;
    uint16_t sizeRequested;
    uint16_t Length;

    pchar Target;
    uintptr_t Offset = 0;
    int Wordsize = 1;

    m_lastError=0;

    // If we are addressing Timers or counters the element size is 2
    if ((Area==S7AreaCT) || (Area==S7AreaTM))
        Wordsize = 2;

    if (WordLen==S7WLBit) // Only one bit can be transferred in S7Protocol when WordLen==S7WLBit
        Amount=1;

    MaxElements=(m_PDULength-18) / Wordsize; // 18 = Reply telegram header
    TotElements=Amount;
    // If we use the internal buffer only, we cannot exced the PDU limit
    if (ptrData==NULL)
    {
        if (TotElements>MaxElements)
            TotElements=MaxElements;
    }

    while ((TotElements>0) && (m_lastError==0))
    {
        NumElements=TotElements;
        if (NumElements>MaxElements)
            NumElements=MaxElements;

        sizeRequested =NumElements * Wordsize;

        Target=pchar(ptrData)+Offset;

        // Setup the telegram
        memcpy(&PDU.H, S7_RW, size_RD);

        // Set DB Number
        PDU.H[27] = Area;
        if (Area==S7AreaDB)
        {
            PDU.H[25] = dBNumber>>8;
            PDU.H[26] = dBNumber & 0x00FF;
        }

        // Adjusts Start and word length
        if ((WordLen == S7WLBit) || (Area==S7AreaCT) || (Area==S7AreaTM))
        {
            Address = LongStart;
            if (WordLen==S7WLBit)
                PDU.H[22]=S7WLBit;
            else {
                if (Area==S7AreaCT)
                    PDU.H[22]=S7WLCounter;
                else
                    PDU.H[22]=S7WLTimer;
            }
        }
        else
            Address = LongStart<<3;

        // Num elements
        PDU.H[23]=NumElements<<8;
        PDU.H[24]=NumElements;

        // Address into the PLC
        PDU.H[30] = Address & 0x000000FF;
        Address = Address >> 8;
        PDU.H[29] = Address & 0x000000FF;
        Address = Address >> 8;
        PDU.H[28] = Address & 0x000000FF;

        if (m_tcpClient->write(&PDU.H[0], size_RD)==size_RD)
        {
            recvISOPacket(&Length);
            if (m_lastError==0)
            {
                if (Length>=18)
                {
                    if ((Length-18==sizeRequested) && (PDU.H[31]==0xFF))
                    {
                        if (ptrData!=NULL)
                            memcpy(Target, &PDU.DATA[0], sizeRequested); // Copies in the user's buffer
                        Offset+=sizeRequested;
                    }
                    else
                        m_lastError = errS7DataRead;
                }
                else
                    m_lastError = errS7InvalidPDU;
            }
        }
        else
            m_lastError = errTCPDataSend;

        TotElements -= NumElements;
        LongStart += NumElements*Wordsize;
    }
    return m_lastError;
}

int S7Client::readArea(int Area, uint16_t dBNumber, uint16_t Start, uint16_t Amount, void *ptrData)
{
    return readArea(Area, dBNumber, Start, Amount, S7WLByte, ptrData);
}

int S7Client::readBit(int Area, uint16_t dBNumber, uint16_t BitStart, bool &Bit)
{
    return readArea(Area, dBNumber, BitStart, 1, S7WLBit, &Bit);
}

int S7Client::writeArea(int Area, uint16_t dBNumber, uint16_t Start, uint16_t Amount, int WordLen, void *ptrData)
{
    unsigned long Address;
    unsigned long LongStart=Start;
    uint16_t NumElements;
    uint16_t MaxElements;
    uint16_t TotElements;
    uint16_t Datasize;
    uint16_t Isosize;
    uint16_t Length;

    pchar Source;
    uintptr_t Offset = 0;
    int Wordsize = 1;

    m_lastError=0;

    // If we are addressing Timers or counters the element size is 2
    if ((Area==S7AreaCT) || (Area==S7AreaTM))
        Wordsize = 2;

    if (WordLen==S7WLBit) // Only one bit can be transferred in S7Protocol when WordLen==S7WLBit
        Amount=1;

    MaxElements=(m_PDULength-35) / Wordsize; // 35 = Write telegram header
    TotElements=Amount;
    if (ptrData==NULL)
    {
        if (TotElements>MaxElements)
            TotElements=MaxElements;
    }

    while ((TotElements>0) && (m_lastError==0))
    {
        NumElements=TotElements;
        if (NumElements>MaxElements)
            NumElements=MaxElements;
        // If we use the internal buffer only, we cannot exced the PDU limit
        Datasize=NumElements*Wordsize;
        Isosize=size_WR+Datasize;

        // Setup the telegram
        memcpy(&PDU.H, S7_RW, size_WR);
        // Whole telegram size
        PDU.H[2]=Isosize>>8;
        PDU.H[3]=Isosize & 0x00FF;
        // Data Length
        Length=Datasize+4;
        PDU.H[15]=Length>>8;
        PDU.H[16]=Length & 0x00FF;
        // Function
        PDU.H[17]=0x05;
        // Set DB Number
        PDU.H[27] = Area;
        if (Area==S7AreaDB)
        {
            PDU.H[25] = dBNumber>>8;
            PDU.H[26] = dBNumber & 0x00FF;
        }
        // Adjusts Start and word length
        if ((WordLen == S7WLBit) || (Area==S7AreaCT) || (Area==S7AreaTM))
        {
            Address = LongStart;
            Length = Datasize;
            if (WordLen==S7WLBit)
                PDU.H[22]=S7WLBit;
            else {
                if (Area==S7AreaCT)
                    PDU.H[22]=S7WLCounter;
                else
                    PDU.H[22]=S7WLTimer;
            }
        }
        else
        {
            Address = LongStart<<3;
            Length = Datasize<<3;
        }
        // Num elements
        PDU.H[23]=NumElements<<8;
        PDU.H[24]=NumElements;
        // Address into the PLC
        PDU.H[30] = Address & 0x000000FF;
        Address = Address >> 8;
        PDU.H[29] = Address & 0x000000FF;
        Address = Address >> 8;
        PDU.H[28] = Address & 0x000000FF;

        // Transport size
        switch (WordLen)
        {
        case S7WLBit:
            PDU.H[32] = TS_ResBit;
            break;
        case S7WLCounter:
        case S7WLTimer:
            PDU.H[32] = TS_ResOctet;
            break;
        default:
            PDU.H[32] = TS_ResByte; // byte/word/dword etc.
            break;
        };

        // Length
        PDU.H[33]=Length>>8;
        PDU.H[34]=Length & 0x00FF;
        // Copy data
        Source=pchar(ptrData)+Offset;
        if (ptrData!=NULL)
            memcpy(&PDU.RAW[35], Source, Datasize);

        if (m_tcpClient->write(&PDU.H[0], Isosize)==Isosize)
        {
            recvISOPacket(&Length);
            if (m_lastError==0)
            {
                if (Length==15)
                {
                    if ((PDU.H[27]!=0x00) || (PDU.H[28]!=0x00) || (PDU.H[31]!=0xFF))
                        m_lastError = errS7DataWrite;
                }
                else
                    m_lastError = errS7InvalidPDU;
            }
        }
        else
            m_lastError = errTCPDataSend;

        Offset+=Datasize;
        TotElements -= NumElements;
        LongStart += NumElements*Wordsize;
    }
    return m_lastError;
}
int S7Client::writeArea(int Area, uint16_t dBNumber, uint16_t Start, uint16_t Amount, void *ptrData)
{
    return writeArea(Area, dBNumber, Start, Amount, S7WLByte, ptrData);
}
int S7Client::writeBit(int Area, uint16_t dBNumber, uint16_t BitIndex, bool Bit)
{
    bool BitToWrite=Bit;
    return writeArea(Area, dBNumber, BitIndex, 1, S7WLBit, &BitToWrite);
}
int S7Client::writeBit(int Area, uint16_t dBNumber, uint16_t ByteIndex, uint16_t BitInByte, bool Bit)
{
    bool BitToWrite=Bit;
    return writeArea(Area, dBNumber, ByteIndex*8+BitInByte, 1, S7WLBit, &BitToWrite);
}

int S7Client::getDBSize(uint16_t dBNumber, uint16_t *size)
{
    uint16_t Length;
    m_lastError=0;
    *size=0;
    // Setup the telegram
    memcpy(&PDU.H[0], S7_BI, sizeof(S7_BI));
    // Set DB Number
    PDU.RAW[31]=(dBNumber / 10000)+0x30;
    dBNumber=dBNumber % 10000;
    PDU.RAW[32]=(dBNumber / 1000)+0x30;
    dBNumber=dBNumber % 1000;
    PDU.RAW[33]=(dBNumber / 100)+0x30;
    dBNumber=dBNumber % 100;
    PDU.RAW[34]=(dBNumber / 10)+0x30;
    dBNumber=dBNumber % 10;
    PDU.RAW[35]=(dBNumber / 1)+0x30;
    if (m_tcpClient->write(&PDU.H[0], sizeof(S7_BI))==sizeof(S7_BI))
    {
        recvISOPacket(&Length);
        if (m_lastError==0)
        {
            if (Length>25) // 26 is the minimum expected
            {
                if ((PDU.RAW[37]==0x00) && (PDU.RAW[38]==0x00) && (PDU.RAW[39]==0xFF))
                {
                    *size=PDU.RAW[83];
                    *size=(*size<<8)+PDU.RAW[84];
                }
                else
                    m_lastError = errS7Function;
            }
            else
                m_lastError = errS7InvalidPDU;
        }
    }
    else
        m_lastError = errTCPDataSend;

    return m_lastError;
}
int S7Client::dBGet(uint16_t dBNumber, void *ptrData, uint16_t *size)
{
    uint16_t Length;
    int Result;

    Result=getDBSize(dBNumber, &Length);
    if (Result==0)
    {
        if (Length<=*size) // Check if the buffer supplied is big enough
        {
            Result=readArea(S7AreaDB, dBNumber, 0, Length, ptrData);
            if (Result==0)
                *size=Length;
        }
        else
            Result=errBufferTooSmall;
    }

    return Result;
}
int S7Client::plcStop()
{
    uint16_t Length;
    m_lastError=0;
    // Setup the telegram
    memcpy(&PDU.H, S7_STOP, sizeof(S7_STOP));
    if (m_tcpClient->write(&PDU.H[0], sizeof(S7_STOP))==sizeof(S7_STOP))
    {
        recvISOPacket(&Length);
        if (m_lastError==0)
        {
            if (Length>12) // 13 is the minimum expected
            {
                if ((PDU.H[27]!=0x00) || (PDU.H[28]!=0x00))
                    m_lastError = errS7Function;
            }
            else
                m_lastError = errS7InvalidPDU;
        }
    }
    else
        m_lastError = errTCPDataSend;

    return m_lastError;
}
int S7Client::plcStart()
{
    uint16_t Length;
    m_lastError=0;
    // Setup the telegram
    memcpy(&PDU.H, S7_START, sizeof(S7_START));
    if (m_tcpClient->write(&PDU.H[0], sizeof(S7_START))==sizeof(S7_START))
    {
        recvISOPacket(&Length);
        if (m_lastError==0)
        {
            if (Length>12) // 13 is the minimum expected
            {
                if ((PDU.H[27]!=0x00) || (PDU.H[28]!=0x00))
                    m_lastError = errS7Function;
            }
            else
                m_lastError = errS7InvalidPDU;
        }
    }
    else
        m_lastError = errTCPDataSend;

    return m_lastError;
}
int S7Client::getPlcStatus(int *status)
{
    uint16_t Length;
    m_lastError=0;
    // Setup the telegram
    memcpy(&PDU.H, S7_PLCGETS, sizeof(S7_PLCGETS));
    if (m_tcpClient->write(&PDU.H[0], sizeof(S7_PLCGETS))==sizeof(S7_PLCGETS))
    {
        recvISOPacket(&Length);
        if (m_lastError==0)
        {
            if (Length>53) // 54 is the minimum expected
            {
                switch (PDU.RAW[54])
                {
                case S7CpuStatusUnknown :
                case S7CpuStatusRun     :
                case S7CpuStatusStop    : *status=PDU.RAW[54];
                    break;
                default :
                    // Since RUN status is always 0x08 for all CPUs and CPs, STOP status
                    // sometime can be coded as 0x03 (especially for old cpu...)
                    *status=S7CpuStatusStop;
                }
            }
            else
                m_lastError = errS7InvalidPDU;
        }
    }
    else
        m_lastError = errTCPDataSend;

    return m_lastError;
}
int S7Client::isoExchangeBuffer(uint16_t *size)
{
    m_lastError=0;

    if (m_tcpClient->write(&PDU.H[0], (qint64) (size))==*size)
        recvISOPacket(size);
    else
        m_lastError = errTCPDataSend;

    return m_lastError;
}

