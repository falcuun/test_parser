#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/// @brief Parser State Machine.
/// @param parser Parser whose state will be controlled
/// @param output_payload Pointer to array for payload data
/// @param input_data  The byte that is to be checked.
/// @return retunrs Failure or Success based on if there is any errors
uint8_t parser_appendByte(parser_t *parser, uint8_t *output_payload, uint8_t input_data)
{
    switch (parser->state)
    {
    case STATE_LOOKING_FOR_START_BYTE_0:
        if (input_data == START_BYTE_0)
        {
            parser->state = STATE_LOOKING_FOR_START_BYTE_1;
        }
        else
        {
            return RESULT_FAILURE;
        }
        break;

    case STATE_LOOKING_FOR_START_BYTE_1:
        if (input_data == START_BYTE_1)
        {
            parser->state = STATE_PARSING_LENGTH;
        }
        else
        {
            parser->state = STATE_LOOKING_FOR_START_BYTE_0;
        }
        break;
    case STATE_PARSING_LENGTH:
        parser->payload_length = input_data;
        parser->state = STATE_PARSING_PAYLOAD;
        break;
    case STATE_PARSING_PAYLOAD:
        if (parser->payload_buffer_index == 0)
        {
            parser->payload_buffer = (uint8_t *)malloc(sizeof(uint8_t *) * parser->payload_length);
        }
        parser->payload_buffer[parser->payload_buffer_index] = input_data;
        ++parser->payload_buffer_index;

        if (parser->payload_buffer_index >= (parser->frame_len - FRAME_SIZE_OFFSET))
        {
            if (parser->payload_buffer_index - 2 > parser->payload_length)
            {
                return RESULT_FAILURE;
            }
            parser->state = STATE_PARSING_CHECKSUM;
        }
        break;
    case STATE_PARSING_CHECKSUM:
        parser->checksum_buffer[parser->checksum_buffer_index] = input_data;
        if (parser->checksum_buffer_index >= 1)
        {
            if (parser->payload_length < parser->payload_buffer_index)
            {
                return RESULT_FAILURE;
            }
            output_payload = (uint8_t *)malloc(sizeof(uint8_t *) * parser->payload_length);
            parser->calculated_checksum = (parser->checksum_buffer[0] << 8 | parser->checksum_buffer[1]);
            memcpy(output_payload, parser->payload_buffer, parser->payload_length);
            parser->state = STATE_FRAME_RECEIVED;
            return RESULT_SUCCESS;
        }
        ++parser->checksum_buffer_index;
        break;
    case STATE_FRAME_RECEIVED:
        parser->state = STATE_LOOKING_FOR_START_BYTE_0;
        break;
    default:
        parser->state = STATE_LOOKING_FOR_START_BYTE_0;
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

typedef struct frame
{
    uint8_t *frame_message;
    uint8_t frame_len;
} frame_t;

/// @brief Runs the frame validation process.
/// @param frame_message The Whole frame including Start Bytes, Payload Len, Payload and Checksum.
/// @param frame_len The length of the entire frame (all the bytes).
void run_payload(frame_t *frame)
{
    parser_t parser;
    uint8_t *output_payload;
    uint8_t i;

    parser_init(&parser, frame->frame_len);

    for (i = 0; i < frame->frame_len; i++)
    {
        uint8_t byte_parsed = parser_appendByte(&parser, output_payload, frame->frame_message[i]);
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
    frame_t frame;
    uint8_t validFrame1[14] = {0xFE, 0xFB, 0x09, 0x08, 0x01, 0xC0, 0xDE, 0xAB, 0x81, 0xC0, 0xDE, 0x5C, 0x8B, 0xD1};
    frame.frame_message = validFrame1;
    frame.frame_len = sizeof(validFrame1);
    run_payload(&frame);

    uint8_t validFrame2[8] = {0xFE, 0xFB, 0x03, 0xAB, 0xCD, 0xAB, 0x4A, 0x25};
    frame.frame_message = validFrame2;
    frame.frame_len = sizeof(validFrame2);
    run_payload(&frame);

    uint8_t validFrame3[10] = {0xFE, 0xFB, 0x05, 0x01, 0x02, 0x03, 0x04, 0x6E, 0x8C, 0x78};
    frame.frame_message = validFrame3;
    frame.frame_len = sizeof(validFrame3);
    run_payload(&frame);

    uint8_t validFrame4[12] = {0xFE, 0xFB, 0x07, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0x5A, 0x86};
    frame.frame_message = validFrame4;
    frame.frame_len = sizeof(validFrame4);
    run_payload(&frame);

    uint8_t validFrame5[14] = {0xFE, 0xFB, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x16, 0xB2, 0x3A};
    frame.frame_message = validFrame5;
    frame.frame_len = sizeof(validFrame5);
    run_payload(&frame);

    uint8_t validFrame6[16] = {0xFE, 0xFB, 0x0B, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0x6B, 0x1C, 0xCB, 0xC3};
    frame.frame_message = validFrame6;
    frame.frame_len = sizeof(validFrame6);
    run_payload(&frame);

    uint8_t validFrame7[18] = {0xFE, 0xFB, 0x0D, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0xC1, 0x7D, 0x10};
    frame.frame_message = validFrame7;
    frame.frame_len = sizeof(validFrame7);
    run_payload(&frame);

    uint8_t validFrame8[20] = {0xFE, 0xFB, 0x0F, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0x1E, 0xB1, 0x17, 0x69, 0x8C};
    frame.frame_message = validFrame8;
    frame.frame_len = sizeof(validFrame8);
    run_payload(&frame);

    uint8_t validFrame9[22] = {0xFE, 0xFB, 0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0xCC, 0x99};
    frame.frame_message = validFrame9;
    frame.frame_len = sizeof(validFrame9);
    run_payload(&frame);

    uint8_t validFrame10[24] = {0xFE, 0xFB, 0x13, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0x7E, 0xB4, 0x29, 0xBB};
    frame.frame_message = validFrame10;
    frame.frame_len = sizeof(validFrame10);
    run_payload(&frame);
}

void TEST_TWO_five_valid_frames_five_invalid_frames_singles(void)
{
    frame_t frame;

    uint8_t invalidFrame1[10] = {0xFE, 0xFC, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    frame.frame_message = invalidFrame1;
    frame.frame_len = sizeof(invalidFrame1);
    run_payload(&frame);

    uint8_t invalidFrame2[7] = {0xFE, 0xFB, 0x03, 0x01, 0x02, 0x03};
    frame.frame_message = invalidFrame2;
    frame.frame_len = sizeof(invalidFrame2);
    run_payload(&frame);

    uint8_t invalidFrame3[9] = {0xFD, 0xFB, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    frame.frame_message = invalidFrame3;
    frame.frame_len = sizeof(invalidFrame3);
    run_payload(&frame);

    uint8_t invalidFrame4[8] = {0xFE, 0xFB, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05};
    frame.frame_message = invalidFrame4;
    frame.frame_len = sizeof(invalidFrame4);
    run_payload(&frame);

    uint8_t invalidFrame5[12] = {0xFE, 0xFB, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x09, 0x07, 0x08};
    frame.frame_message = invalidFrame5;
    frame.frame_len = sizeof(invalidFrame5);
    run_payload(&frame);

    uint8_t validFrame6[16] = {0xFE, 0xFB, 0x0B, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0x6B, 0x1C, 0xCB, 0xC3};
    frame.frame_message = validFrame6;
    frame.frame_len = sizeof(validFrame6);
    run_payload(&frame);

    uint8_t validFrame7[18] = {0xFE, 0xFB, 0x0D, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0xC1, 0x7D, 0x10};
    frame.frame_message = validFrame7;
    frame.frame_len = sizeof(validFrame7);
    run_payload(&frame);

    uint8_t validFrame8[20] = {0xFE, 0xFB, 0x0F, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0x1E, 0xB1, 0x17, 0x69, 0x8C};
    frame.frame_message = validFrame8;
    frame.frame_len = sizeof(validFrame8);
    run_payload(&frame);

    uint8_t validFrame9[22] = {0xFE, 0xFB, 0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0xCC, 0x99};
    frame.frame_message = validFrame9;
    frame.frame_len = sizeof(validFrame9);
    run_payload(&frame);

    uint8_t validFrame10[24] = {0xFE, 0xFB, 0x13, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0x7E, 0xB4, 0x29, 0xBB};
    frame.frame_message = validFrame10;
    frame.frame_len = sizeof(validFrame10);
    run_payload(&frame);
}

int main()
{
    TEST_ONE_eleven_valid_frames_singles();
    TEST_TWO_five_valid_frames_five_invalid_frames_singles();
    return 0;
}