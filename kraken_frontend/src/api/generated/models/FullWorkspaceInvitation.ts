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
import type { SimpleUser } from './SimpleUser';
import {
    SimpleUserFromJSON,
    SimpleUserFromJSONTyped,
    SimpleUserToJSON,
} from './SimpleUser';
import type { SimpleWorkspace } from './SimpleWorkspace';
import {
    SimpleWorkspaceFromJSON,
    SimpleWorkspaceFromJSONTyped,
    SimpleWorkspaceToJSON,
} from './SimpleWorkspace';

/**
 * The full representation of an invitation to a workspace
 * @export
 * @interface FullWorkspaceInvitation
 */
export interface FullWorkspaceInvitation {
    /**
     * The uuid of the invitation
     * @type {string}
     * @memberof FullWorkspaceInvitation
     */
    uuid: string;
    /**
     * 
     * @type {SimpleWorkspace}
     * @memberof FullWorkspaceInvitation
     */
    workspace: SimpleWorkspace;
    /**
     * 
     * @type {SimpleUser}
     * @memberof FullWorkspaceInvitation
     */
    from: SimpleUser;
    /**
     * 
     * @type {SimpleUser}
     * @memberof FullWorkspaceInvitation
     */
    target: SimpleUser;
}

/**
 * Check if a given object implements the FullWorkspaceInvitation interface.
 */
export function instanceOfFullWorkspaceInvitation(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuid" in value;
    isInstance = isInstance && "workspace" in value;
    isInstance = isInstance && "from" in value;
    isInstance = isInstance && "target" in value;

    return isInstance;
}

export function FullWorkspaceInvitationFromJSON(json: any): FullWorkspaceInvitation {
    return FullWorkspaceInvitationFromJSONTyped(json, false);
}

export function FullWorkspaceInvitationFromJSONTyped(json: any, ignoreDiscriminator: boolean): FullWorkspaceInvitation {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuid': json['uuid'],
        'workspace': SimpleWorkspaceFromJSON(json['workspace']),
        'from': SimpleUserFromJSON(json['from']),
        'target': SimpleUserFromJSON(json['target']),
    };
}

export function FullWorkspaceInvitationToJSON(value?: FullWorkspaceInvitation | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'uuid': value.uuid,
        'workspace': SimpleWorkspaceToJSON(value.workspace),
        'from': SimpleUserToJSON(value.from),
        'target': SimpleUserToJSON(value.target),
    };
}

