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
import type { EditorTargetOneOf1Finding } from './EditorTargetOneOf1Finding';
import {
    EditorTargetOneOf1FindingFromJSON,
    EditorTargetOneOf1FindingFromJSONTyped,
    EditorTargetOneOf1FindingToJSON,
} from './EditorTargetOneOf1Finding';

/**
 * 
 * @export
 * @interface EditorTargetOneOf1
 */
export interface EditorTargetOneOf1 {
    /**
     * 
     * @type {EditorTargetOneOf1Finding}
     * @memberof EditorTargetOneOf1
     */
    finding: EditorTargetOneOf1Finding;
}

/**
 * Check if a given object implements the EditorTargetOneOf1 interface.
 */
export function instanceOfEditorTargetOneOf1(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "finding" in value;

    return isInstance;
}

export function EditorTargetOneOf1FromJSON(json: any): EditorTargetOneOf1 {
    return EditorTargetOneOf1FromJSONTyped(json, false);
}

export function EditorTargetOneOf1FromJSONTyped(json: any, ignoreDiscriminator: boolean): EditorTargetOneOf1 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'finding': EditorTargetOneOf1FindingFromJSON(json['Finding']),
    };
}

export function EditorTargetOneOf1ToJSON(value?: EditorTargetOneOf1 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Finding': EditorTargetOneOf1FindingToJSON(value.finding),
    };
}

