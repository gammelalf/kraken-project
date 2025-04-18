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
 * Request to do DNS TXT scanning & parsing
 * @export
 * @interface DnsTxtScanRequest
 */
export interface DnsTxtScanRequest {
    /**
     * The leech to use
     * 
     * Leave empty to use a random leech
     * @type {string}
     * @memberof DnsTxtScanRequest
     */
    leechUuid?: string | null;
    /**
     * The domains to resolve
     * @type {Array<string>}
     * @memberof DnsTxtScanRequest
     */
    targets: Array<string>;
    /**
     * The workspace to execute the attack in
     * @type {string}
     * @memberof DnsTxtScanRequest
     */
    workspaceUuid: string;
}

/**
 * Check if a given object implements the DnsTxtScanRequest interface.
 */
export function instanceOfDnsTxtScanRequest(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "targets" in value;
    isInstance = isInstance && "workspaceUuid" in value;

    return isInstance;
}

export function DnsTxtScanRequestFromJSON(json: any): DnsTxtScanRequest {
    return DnsTxtScanRequestFromJSONTyped(json, false);
}

export function DnsTxtScanRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): DnsTxtScanRequest {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'leechUuid': !exists(json, 'leech_uuid') ? undefined : json['leech_uuid'],
        'targets': json['targets'],
        'workspaceUuid': json['workspace_uuid'],
    };
}

export function DnsTxtScanRequestToJSON(value?: DnsTxtScanRequest | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'leech_uuid': value.leechUuid,
        'targets': value.targets,
        'workspace_uuid': value.workspaceUuid,
    };
}

