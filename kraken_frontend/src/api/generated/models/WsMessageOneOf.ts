/* tslint:disable */
/* eslint-disable */
/**
 * kraken
 * The core component of kraken-project
 *
 * The version of the OpenAPI document: 0.5.0
 * Contact: git@omikron.dev
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { exists, mapValues } from '../runtime';
/**
 * An invalid message was received.
 * 
 * This message type is sent to the client.
 * @export
 * @interface WsMessageOneOf
 */
export interface WsMessageOneOf {
    /**
     * 
     * @type {string}
     * @memberof WsMessageOneOf
     */
    type: WsMessageOneOfTypeEnum;
}


/**
 * @export
 */
export const WsMessageOneOfTypeEnum = {
    InvalidMessage: 'InvalidMessage'
} as const;
export type WsMessageOneOfTypeEnum = typeof WsMessageOneOfTypeEnum[keyof typeof WsMessageOneOfTypeEnum];


/**
 * Check if a given object implements the WsMessageOneOf interface.
 */
export function instanceOfWsMessageOneOf(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function WsMessageOneOfFromJSON(json: any): WsMessageOneOf {
    return WsMessageOneOfFromJSONTyped(json, false);
}

export function WsMessageOneOfFromJSONTyped(json: any, ignoreDiscriminator: boolean): WsMessageOneOf {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'type': json['type'],
    };
}

export function WsMessageOneOfToJSON(value?: WsMessageOneOf | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'type': value.type,
    };
}

