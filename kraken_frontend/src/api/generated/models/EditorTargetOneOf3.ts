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
import type { EditorTargetOneOf3WorkspaceNotes } from './EditorTargetOneOf3WorkspaceNotes';
import {
    EditorTargetOneOf3WorkspaceNotesFromJSON,
    EditorTargetOneOf3WorkspaceNotesFromJSONTyped,
    EditorTargetOneOf3WorkspaceNotesToJSON,
} from './EditorTargetOneOf3WorkspaceNotes';

/**
 * 
 * @export
 * @interface EditorTargetOneOf3
 */
export interface EditorTargetOneOf3 {
    /**
     * 
     * @type {EditorTargetOneOf3WorkspaceNotes}
     * @memberof EditorTargetOneOf3
     */
    workspaceNotes: EditorTargetOneOf3WorkspaceNotes;
}

/**
 * Check if a given object implements the EditorTargetOneOf3 interface.
 */
export function instanceOfEditorTargetOneOf3(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "workspaceNotes" in value;

    return isInstance;
}

export function EditorTargetOneOf3FromJSON(json: any): EditorTargetOneOf3 {
    return EditorTargetOneOf3FromJSONTyped(json, false);
}

export function EditorTargetOneOf3FromJSONTyped(json: any, ignoreDiscriminator: boolean): EditorTargetOneOf3 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'workspaceNotes': EditorTargetOneOf3WorkspaceNotesFromJSON(json['WorkspaceNotes']),
    };
}

export function EditorTargetOneOf3ToJSON(value?: EditorTargetOneOf3 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'WorkspaceNotes': EditorTargetOneOf3WorkspaceNotesToJSON(value.workspaceNotes),
    };
}

