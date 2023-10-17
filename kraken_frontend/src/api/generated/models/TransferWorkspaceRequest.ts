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
/**
 * The request to transfer a workspace to another account
 * @export
 * @interface TransferWorkspaceRequest
 */
export interface TransferWorkspaceRequest {
    /**
     * The uuid of the user that should receive the workspace
     * @type {string}
     * @memberof TransferWorkspaceRequest
     */
    user: string;
}

/**
 * Check if a given object implements the TransferWorkspaceRequest interface.
 */
export function instanceOfTransferWorkspaceRequest(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "user" in value;

    return isInstance;
}

export function TransferWorkspaceRequestFromJSON(json: any): TransferWorkspaceRequest {
    return TransferWorkspaceRequestFromJSONTyped(json, false);
}

export function TransferWorkspaceRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): TransferWorkspaceRequest {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'user': json['user'],
    };
}

export function TransferWorkspaceRequestToJSON(value?: TransferWorkspaceRequest | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'user': value.user,
    };
}

