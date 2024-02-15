/* tslint:disable */
/* eslint-disable */
/**
 * kraken
 * The core component of kraken-project
 *
 * The version of the OpenAPI document: 0.1.0
 * Contact: git@omikron.dev
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { exists, mapValues } from '../runtime';
import type { Change } from './Change';
import {
    ChangeFromJSON,
    ChangeFromJSONTyped,
    ChangeToJSON,
} from './Change';
import type { EditorTarget } from './EditorTarget';
import {
    EditorTargetFromJSON,
    EditorTargetFromJSONTyped,
    EditorTargetToJSON,
} from './EditorTarget';
import type { SimpleUser } from './SimpleUser';
import {
    SimpleUserFromJSON,
    SimpleUserFromJSONTyped,
    SimpleUserToJSON,
} from './SimpleUser';

/**
 * A finding definition was updated
 * @export
 * @interface WsMessageOneOf26
 */
export interface WsMessageOneOf26 {
    /**
     * 
     * @type {Change}
     * @memberof WsMessageOneOf26
     */
    change: Change;
    /**
     * 
     * @type {SimpleUser}
     * @memberof WsMessageOneOf26
     */
    user: SimpleUser;
    /**
     * 
     * @type {EditorTarget}
     * @memberof WsMessageOneOf26
     */
    target: EditorTarget;
    /**
     * 
     * @type {string}
     * @memberof WsMessageOneOf26
     */
    type: WsMessageOneOf26TypeEnum;
}


/**
 * @export
 */
export const WsMessageOneOf26TypeEnum = {
    EditorChangedContent: 'EditorChangedContent'
} as const;
export type WsMessageOneOf26TypeEnum = typeof WsMessageOneOf26TypeEnum[keyof typeof WsMessageOneOf26TypeEnum];


/**
 * Check if a given object implements the WsMessageOneOf26 interface.
 */
export function instanceOfWsMessageOneOf26(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "change" in value;
    isInstance = isInstance && "user" in value;
    isInstance = isInstance && "target" in value;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function WsMessageOneOf26FromJSON(json: any): WsMessageOneOf26 {
    return WsMessageOneOf26FromJSONTyped(json, false);
}

export function WsMessageOneOf26FromJSONTyped(json: any, ignoreDiscriminator: boolean): WsMessageOneOf26 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'change': ChangeFromJSON(json['change']),
        'user': SimpleUserFromJSON(json['user']),
        'target': EditorTargetFromJSON(json['target']),
        'type': json['type'],
    };
}

export function WsMessageOneOf26ToJSON(value?: WsMessageOneOf26 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'change': ChangeToJSON(value.change),
        'user': SimpleUserToJSON(value.user),
        'target': EditorTargetToJSON(value.target),
        'type': value.type,
    };
}

