#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define START_BYTE_0 0xFE
#define START_BYTE_1 0xFB
#define MAX_PAYLOAD_LENGTH 255

#define FRAME_SIZE_OFFSET 5 // To account for frame data (3 bytes in front (Start Bytes, Payload Length) and 2 in back (Checksum))

enum PARSING_RESULT
{
    RESULT_SUCCESS = 0xAA,
    RESULT_FAILURE = 0xFF
};

typedef enum
{
    STATE_LOOKING_FOR_START_BYTE_0,
    STATE_LOOKING_FOR_START_BYTE_1,
    STATE_PARSING_LENGTH,
    STATE_PARSING_PAYLOAD,
    STATE_PARSING_CHECKSUM,
    STATE_FRAME_RECEIVED
} parser_state_t;

typedef struct parser
{
    uint8_t frame_len; // The length of the entire frame

    parser_state_t state; // Current State in the state machine.

    uint8_t *payload_buffer;      // The payload
    uint8_t payload_buffer_index; // Index to iterate over data(payload)

    uint8_t payload_length; // The length of Payload

    uint8_t checksum_buffer[2]; // Last Two Bytes (Fletcher16 Checksum split in two (uint8_t) bytes)
    uint8_t checksum_buffer_index;

    uint16_t calculated_checksum;
} parser_t;

void parser_init(parser_t *parser, uint8_t frame_len);

uint16_t fletcher16(uint8_t *data, int count);
/// @brief Calculates Fletcher16 checksum
/// @param data Pointer to array which is to be calculated
/// @param count amount of elements in the array
/// @return uint16 byte of the checksum 
uint16_t fletcher16(uint8_t *data, int count)
{
    uint16_t sum1 = 0;
    uint16_t sum2 = 0;
    int index;
    for (index = 0; index < count; ++index)
    {
        sum1 = (sum1 + data[index]) % 255;
        sum2 = (sum2 + sum1) % 255;
    }
    return (sum2 << 8) | sum1;
}

typedef struct parser_input
{
    parser_t *parser;
    uint8_t *output_payload;
    uint8_t input_data;
}parser_input_t;

/// @brief Parser State Machine.    
/// @param parser Parser whose state will be controlled
/// @param output_payload Pointer to array for payload data 
/// @param input_data  The byte that is to be checked.
/// @return retunrs Failure or Success based on if there is any errors 
uint8_t parser_appendByte(parser_input_t *input_t)
{
    switch (input_t->parser->state)
    {
    case STATE_LOOKING_FOR_START_BYTE_0:
        if (input_t->input_data == START_BYTE_0)
        {
            input_t->parser->state = STATE_LOOKING_FOR_START_BYTE_1;
        }
        else
        {
            return RESULT_FAILURE;
        }
        break;

    case STATE_LOOKING_FOR_START_BYTE_1:
        if (input_t->input_data == START_BYTE_1){input_t->parser->state = STATE_PARSING_LENGTH;}
        else{input_t->parser->state = STATE_LOOKING_FOR_START_BYTE_0;}
        break;
    case STATE_PARSING_LENGTH:
        input_t->parser->payload_length = input_t->input_data;
        input_t->parser->state = STATE_PARSING_PAYLOAD;
        break;
    case STATE_PARSING_PAYLOAD:
        if (input_t->parser->payload_buffer_index == 0)
        {
            input_t->parser->payload_buffer = (uint8_t *)malloc(sizeof(uint8_t *) * input_t->parser->payload_length);
        }
        input_t->parser->payload_buffer[input_t->parser->payload_buffer_index] = input_t->input_data;
        ++input_t->parser->payload_buffer_index;

        if (input_t->parser->payload_buffer_index >= (input_t->parser->frame_len - FRAME_SIZE_OFFSET))
        {
            if (input_t->parser->payload_buffer_index - 2 > input_t->parser->payload_length)
            {
                return RESULT_FAILURE;
            }
            input_t->parser->state = STATE_PARSING_CHECKSUM;
        }
        break;
    case STATE_PARSING_CHECKSUM:
        input_t->parser->checksum_buffer[input_t->parser->checksum_buffer_index] = input_t->input_data;
        if (input_t->parser->checksum_buffer_index >= 1)
        {
            if (input_t->parser->payload_length < input_t->parser->payload_buffer_index)
            {
                return RESULT_FAILURE;
            }
            input_t->output_payload = (uint8_t *)malloc(sizeof(uint8_t *) * input_t->parser->payload_length);
            input_t->parser->calculated_checksum = (input_t->parser->checksum_buffer[0] << 8 | input_t->parser->checksum_buffer[1]);
            memcpy(input_t->output_payload, input_t->parser->payload_buffer, input_t->parser->payload_length);
            input_t->parser->state = STATE_FRAME_RECEIVED;
            return RESULT_SUCCESS;
        }
        ++input_t->parser->checksum_buffer_index;
        break;
    case STATE_FRAME_RECEIVED:
        input_t->parser->state = STATE_LOOKING_FOR_START_BYTE_0;
        break;
    default:
        input_t->parser->state = STATE_LOOKING_FOR_START_BYTE_0;
    }
    return RESULT_SUCCESS;
}

/// @brief Initializes and resets the parser
/// @param parser Parser to be initialized/reset
/// @param frame_len Length of the frame that's to be passed to parser. 
void parser_init(parser_t *parser, uint8_t frame_len)
{
    parser->frame_len = frame_len;
    parser->state = STATE_LOOKING_FOR_START_BYTE_0;
    parser->payload_buffer_index = 0;
    parser->checksum_buffer_index = 0;
    parser->payload_length = 0;
    parser->calculated_checksum = 0;
}

/*
frame_t *parse(uint8_t message[], size_t message_len)
{
    frame_t *frame = (frame_t *)malloc(sizeof(frame_t));
    if (message_len < 5)
    {
        return frame; // Error, message too short.
    }
    frame->start_bytes[0] = message[0];
    frame->start_bytes[1] = message[1];

    frame->len = message[2];
    frame->payload = (uint8_t *)malloc(sizeof(uint8_t) * frame->len);
    uint8_t i = 0;
    for (i = 0; i < frame->len; i++)
    {
        frame->payload[i] = message[i + 3];
    }

    uint16_t test_sum = (message[i+3] << 8) | message[i + 4];
    frame->checksum = test_sum;

    return frame;
}
*/

/// @brief Verifies that received checksum (inside the message)
/// @param data Data to calculate checksum over
/// @param data_len Length of data to calculate
/// @param data_checksum The checksum coming from the payload
/// @return 
bool is_frame_valid(uint8_t *data, uint8_t data_len, uint16_t data_checksum)
{
    if (data_len < 1)
    {
        return false;
    }
    uint16_t expected_checksum = fletcher16(data, data_len);
    if (expected_checksum != data_checksum)
    {
        return false; // Checksum not same/as expected
    }

    return true;
}

/// @brief Calls the verifying function and does the printing of the message for the user.
/// @param parser Parser structure that holds the data and checksum that need to be checked.
void check_frame(parser_t *parser)
{
    if (is_frame_valid(parser->payload_buffer, parser->payload_length, parser->calculated_checksum))
    {
        printf("Payload is Valid!\n");
        printf("Payload Length %d, Checksum: %x, Data: ", parser->payload_length, parser->calculated_checksum);
        for (uint8_t i = 0; i < parser->payload_length; i++)
        {
            printf("%x, ", parser->payload_buffer[i]);
        }
        printf("\n");
    }
    else
    {
        printf("Payload is NOT Valid!\n");
    }
}

/// @brief Runs the frame validation process.
/// @param frame_message The Whole frame including Start Bytes, Payload Len, Payload and Checksum.
/// @param frame_len The length of the entire frame (all the bytes).
void run_payload(uint8_t *frame_message, const uint8_t frame_len)
{
    
    parser_t parser;
    uint8_t *output_payload;
    uint8_t i;
    parser_input_t parsed_data = {
        .parser = &parser,
        .output_payload = output_payload,
    };

    parser_init(&parser, frame_len);

    for (i = 0; i < frame_len; i++)
    {
        parsed_data.input_data = frame_message[i];
        uint8_t byte_parsed = parser_appendByte(&parsed_data);
        if (byte_parsed != RESULT_SUCCESS)
        {
            check_frame(&parser);
            return;
        }
    }

    check_frame(&parser);

    free(parser.payload_buffer);
}

void TEST_ONE_eleven_valid_frames_singles(void)
{
    uint8_t validFrame1[14] = {0xFE, 0xFB, 0x09, 0x08, 0x01, 0xC0, 0xDE, 0xAB, 0x81, 0xC0, 0xDE, 0x5C, 0x8B, 0xD1};
    run_payload(validFrame1, sizeof(validFrame1));

    uint8_t validFrame2[8] = {0xFE, 0xFB, 0x03, 0xAB, 0xCD, 0xAB, 0x4A, 0x25};
    run_payload(validFrame2, sizeof(validFrame2));

    uint8_t validFrame3[10] = {0xFE, 0xFB, 0x05, 0x01, 0x02, 0x03, 0x04, 0x6E, 0x8C, 0x78};
    run_payload(validFrame3, sizeof(validFrame3));

    uint8_t validFrame4[12] = {0xFE, 0xFB, 0x07, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0x5A, 0x86};
    run_payload(validFrame4, sizeof(validFrame4));

    uint8_t validFrame5[14] = {0xFE, 0xFB, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x16, 0xB2, 0x3A};
    run_payload(validFrame5, sizeof(validFrame5));

    uint8_t validFrame6[16] = {0xFE, 0xFB, 0x0B, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0x6B, 0x1C, 0xCB, 0xC3};
    run_payload(validFrame6, sizeof(validFrame6));

    uint8_t validFrame7[18] = {0xFE, 0xFB, 0x0D, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0xC1, 0x7D, 0x10};
    run_payload(validFrame7, sizeof(validFrame7));

    uint8_t validFrame8[20] = {0xFE, 0xFB, 0x0F, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0x1E, 0xB1, 0x17, 0x69, 0x8C};
    run_payload(validFrame8, sizeof(validFrame8));

    uint8_t validFrame9[22] = {0xFE, 0xFB, 0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0xCC, 0x99};
    run_payload(validFrame9, sizeof(validFrame9));

    uint8_t validFrame10[24] = {0xFE, 0xFB, 0x13, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0x7E, 0xB4, 0x29, 0xBB};
    run_payload(validFrame10, sizeof(validFrame10));
}
void TEST_TWO_five_valid_frames_five_invalid_frames_singles(void)
{
    uint8_t invalidFrame1[10] = {0xFE, 0xFC, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    run_payload(invalidFrame1, sizeof(invalidFrame1));
    uint8_t invalidFrame2[7] = {0xFE, 0xFB, 0x03, 0x01, 0x02, 0x03};
    run_payload(invalidFrame2, sizeof(invalidFrame2));
    uint8_t invalidFrame3[9] = {0xFD, 0xFB, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    run_payload(invalidFrame3, sizeof(invalidFrame3));
    uint8_t invalidFrame4[8] = {0xFE, 0xFB, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05};
    run_payload(invalidFrame4, sizeof(invalidFrame4));
    uint8_t invalidFrame5[12] = {0xFE, 0xFB, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x09, 0x07, 0x08};
    run_payload(invalidFrame5, sizeof(invalidFrame5));

    uint8_t validFrame6[16] = {0xFE, 0xFB, 0x0B, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0x6B, 0x1C, 0xCB, 0xC3};
    run_payload(validFrame6, sizeof(validFrame6));
    uint8_t validFrame7[18] = {0xFE, 0xFB, 0x0D, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0xC1, 0x7D, 0x10};
    run_payload(validFrame7, sizeof(validFrame7));
    uint8_t validFrame8[20] = {0xFE, 0xFB, 0x0F, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0x1E, 0xB1, 0x17, 0x69, 0x8C};
    run_payload(validFrame8, sizeof(validFrame8));
    uint8_t validFrame9[22] = {0xFE, 0xFB, 0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0xCC, 0x99};
    run_payload(validFrame9, sizeof(validFrame9));
    uint8_t validFrame10[24] = {0xFE, 0xFB, 0x13, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0x7E, 0xB4, 0x29, 0xBB};
    run_payload(validFrame10, sizeof(validFrame10));
}
void TEST_THREE_one_valid_frame_thread(void)
{}

int main()
{
    TEST_ONE_eleven_valid_frames_singles();
    TEST_TWO_five_valid_frames_five_invalid_frames_singles();
    return 0;
}