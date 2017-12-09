#pragma once

enum CONN_STATE_ENUM {
    CS_UNINITIALIZED = 0,
    CS_IDLE,

    CS_LISTEN,
    CS_SYN_SENT,
    CS_SYN_RECV,
    CS_RESET,

    CS_CONNECTED,
    CS_CONNECTED_FULL,

    CS_FIN_WAIT_1, // A

    // this is half cloded state. B got A's is fin, and will not send data.
    // But B can still send data, then A can send ack in response
    CS_CLOSE_WAIT, // B

    // A get ack of his fin
    CS_FIN_WAIT_2, // A

    // B sent his fin
    CS_LAST_ACK, // B
    // the end of side A, wait 2 * MSL and then goto CS_DESTROY
    CS_TIME_WAIT,
    // the end of side B
    CS_DESTROY,

    CS_STATE_COUNT
};

enum {
    ATP_PROC_OK = 0,
    ATP_PROC_ERROR = -1,
    ATP_PROC_FINISH = -2,
    ATP_PROC_CACHE = -3,
    ATP_PROC_DROP = -4,
};

typedef int ATP_PROC_RESULT;