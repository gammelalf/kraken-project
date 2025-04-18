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
import type { Color } from './Color';
import {
    ColorFromJSON,
    ColorFromJSONTyped,
    ColorToJSON,
} from './Color';

/**
 * The full representation of a full workspace tag
 * @export
 * @interface FullWorkspaceTag
 */
export interface FullWorkspaceTag {
    /**
     * The uuid of the workspace tag
     * @type {string}
     * @memberof FullWorkspaceTag
     */
    uuid: string;
    /**
     * The name of the tag
     * @type {string}
     * @memberof FullWorkspaceTag
     */
    name: string;
    /**
     * 
     * @type {Color}
     * @memberof FullWorkspaceTag
     */
    color: Color;
    /**
     * The workspace this tag is linked to
     * @type {string}
     * @memberof FullWorkspaceTag
     */
    workspace: string;
}

/**
 * Check if a given object implements the FullWorkspaceTag interface.
 */
export function instanceOfFullWorkspaceTag(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuid" in value;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "color" in value;
    isInstance = isInstance && "workspace" in value;

    return isInstance;
}

export function FullWorkspaceTagFromJSON(json: any): FullWorkspaceTag {
    return FullWorkspaceTagFromJSONTyped(json, false);
}

export function FullWorkspaceTagFromJSONTyped(json: any, ignoreDiscriminator: boolean): FullWorkspaceTag {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuid': json['uuid'],
        'name': json['name'],
        'color': ColorFromJSON(json['color']),
        'workspace': json['workspace'],
    };
}

export function FullWorkspaceTagToJSON(value?: FullWorkspaceTag | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'uuid': value.uuid,
        'name': value.name,
        'color': ColorToJSON(value.color),
        'workspace': value.workspace,
    };
}

