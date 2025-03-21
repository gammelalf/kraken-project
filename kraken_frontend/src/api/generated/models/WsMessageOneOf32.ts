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
 * A finding has been deleted
 * @export
 * @interface WsMessageOneOf32
 */
export interface WsMessageOneOf32 {
    /**
     * The workspace the deleted finding was in
     * @type {string}
     * @memberof WsMessageOneOf32
     */
    workspace: string;
    /**
     * The finding which has been deleted
     * @type {string}
     * @memberof WsMessageOneOf32
     */
    finding: string;
    /**
     * 
     * @type {string}
     * @memberof WsMessageOneOf32
     */
    type: WsMessageOneOf32TypeEnum;
}


/**
 * @export
 */
export const WsMessageOneOf32TypeEnum = {
    DeletedFinding: 'DeletedFinding'
} as const;
export type WsMessageOneOf32TypeEnum = typeof WsMessageOneOf32TypeEnum[keyof typeof WsMessageOneOf32TypeEnum];


/**
 * Check if a given object implements the WsMessageOneOf32 interface.
 */
export function instanceOfWsMessageOneOf32(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "workspace" in value;
    isInstance = isInstance && "finding" in value;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function WsMessageOneOf32FromJSON(json: any): WsMessageOneOf32 {
    return WsMessageOneOf32FromJSONTyped(json, false);
}

export function WsMessageOneOf32FromJSONTyped(json: any, ignoreDiscriminator: boolean): WsMessageOneOf32 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'workspace': json['workspace'],
        'finding': json['finding'],
        'type': json['type'],
    };
}

export function WsMessageOneOf32ToJSON(value?: WsMessageOneOf32 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'workspace': value.workspace,
        'finding': value.finding,
        'type': value.type,
    };
}

