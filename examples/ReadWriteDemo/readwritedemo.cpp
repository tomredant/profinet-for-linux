/*----------------------------------------------------------------------
Data Read Demo
This demo shows how to read data from the PLC.
A DB with at least 1024 byte into the PLC is needed.
Specify its number into DBNum variable

- For safety, this demo *doesn't write* data into the PLC, try
  yourself to change ReadArea with WriteArea.
- This demo uses ConnectTo() with Rack=0 and Slot=2 (S7300)
  - If you want to connect to S71200/S71500 change them to Rack=0, Slot=0.
  - If you want to connect to S7400 see your hardware configuration.
  - If you want to work with a LOGO 0BA7 or S7200 please refer to the
    documentation and change
    Client.ConnectTo(<IP>, <Rack>, <Slot>);
    with the couple
    Client.SetConnectionParams(<IP>, <LocalTSAP>, <Remote TSAP>);
    Client.Connect();

----------------------------------------------------------------------*/
#include "s7comm.h"
#include <QHostAddress>
#include <QThread>

int main()
{
    QHostAddress plc(((quint32) 192 << 24) + ((quint32) 168 << 16) + ((quint32) 2 << 8) + ((quint32) 10)); // Local Address
    int dBNum = 1; // This DB must be present in your PLC
    char buffer[1024];
    S7Client client;
    int size=100;
    void *target;
    target = &buffer;
    int result=client.connectTo(&plc, 0, 0); //s7 1200 demo.
    QThread::msleep(2000); //wait 2 seconds before connected.
    result=client.readArea(S7AreaDB, // We are requesting DB access
                           dBNum,    // DB Number
                           0,        // Start from byte N.0
                           size,     // We need "Size" bytes
                           target);  // Put them into our target (Buffer or PDU)
    char* output = pchar(target);
    for(int i=0;i<size;i++)
        qDebug() << (unsigned short) output[i];


    //MSB first
    output[86]=0;
    output[87]=0;
    output[88]=0;
    //LSB last
    output[89]=20;
    client.writeArea(S7AreaDB, // We are requesting DB access
                     dBNum,    // DB Number
                     0,        // Start from byte N.0
                     size,     // We need "Size" bytes
                     target);  // Put them into our target (Buffer or PDU)
}



