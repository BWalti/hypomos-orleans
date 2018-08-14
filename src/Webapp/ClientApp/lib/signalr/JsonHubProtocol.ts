// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

import { CompletionMessage, HubMessage, IHubProtocol, InvocationMessage, MessageType, StreamItemMessage } from
    "./IHubProtocol";
import { ILogger, LogLevel } from "./ILogger";
import { NullLogger } from "./Loggers";
import { TextMessageFormat } from "./TextMessageFormat";
import { TransferFormat } from "./Transports";

export const JSON_HUB_PROTOCOL_NAME: string = "json";

export class JsonHubProtocol implements IHubProtocol {

    readonly name = JSON_HUB_PROTOCOL_NAME;
    readonly version: number = 1;

    readonly transferFormat: TransferFormat = TransferFormat.Text;

    parseMessages(input: string, logger: ILogger): HubMessage[] {
        if (!input) {
            return [];
        }

        if (logger === null) {
            logger = new NullLogger();
        }

        // Parse the messages
        const messages = TextMessageFormat.parse(input);

        const hubMessages = [];
        for (const message of messages) {
            const parsedMessage = JSON.parse(message) as HubMessage;
            if (typeof parsedMessage.type !== "number") {
                throw new Error("Invalid payload.");
            }
            switch (parsedMessage.type) {
            case MessageType.Invocation:
                this.isInvocationMessage(parsedMessage);
                break;
            case MessageType.StreamItem:
                this.isStreamItemMessage(parsedMessage);
                break;
            case MessageType.Completion:
                this.isCompletionMessage(parsedMessage);
                break;
            case MessageType.Ping:
                // Single value, no need to validate
                break;
            case MessageType.Close:
                // All optional values, no need to validate
                break;
            default:
                // Future protocol changes can add message types, old clients can ignore them
                logger.log(LogLevel.Information, `Unknown message type '${parsedMessage.type}' ignored.`);
                continue;
            }
            hubMessages.push(parsedMessage);
        }

        return hubMessages;
    }

    writeMessage(message: HubMessage): string {
        return TextMessageFormat.write(JSON.stringify(message));
    }

    private isInvocationMessage(message: InvocationMessage): void {
        this.assertNotEmptyString(message.target, "Invalid payload for Invocation message.");

        if (message.invocationId !== undefined) {
            this.assertNotEmptyString(message.invocationId, "Invalid payload for Invocation message.");
        }
    }

    private isStreamItemMessage(message: StreamItemMessage): void {
        this.assertNotEmptyString(message.invocationId, "Invalid payload for StreamItem message.");

        if (message.item === undefined) {
            throw new Error("Invalid payload for StreamItem message.");
        }
    }

    private isCompletionMessage(message: CompletionMessage): void {
        if (message.result && message.error) {
            throw new Error("Invalid payload for Completion message.");
        }

        if (!message.result && message.error) {
            this.assertNotEmptyString(message.error, "Invalid payload for Completion message.");
        }

        this.assertNotEmptyString(message.invocationId, "Invalid payload for Completion message.");
    }

    private assertNotEmptyString(value: any, errorMessage: string): void {
        if (typeof value !== "string" || value === "") {
            throw new Error(errorMessage);
        }
    }
}