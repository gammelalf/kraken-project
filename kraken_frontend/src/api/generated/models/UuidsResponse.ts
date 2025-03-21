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
 * A common response that contains many uuids
 * @export
 * @interface UuidsResponse
 */
export interface UuidsResponse {
    /**
     * The uuids
     * @type {Array<string>}
     * @memberof UuidsResponse
     */
    uuids: Array<string>;
}

/**
 * Check if a given object implements the UuidsResponse interface.
 */
export function instanceOfUuidsResponse(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuids" in value;

    return isInstance;
}

export function UuidsResponseFromJSON(json: any): UuidsResponse {
    return UuidsResponseFromJSONTyped(json, false);
}

export function UuidsResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): UuidsResponse {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuids': json['uuids'],
    };
}

export function UuidsResponseToJSON(value?: UuidsResponse | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'uuids': value.uuids,
    };
}

