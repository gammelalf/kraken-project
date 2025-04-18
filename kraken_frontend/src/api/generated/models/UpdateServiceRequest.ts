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
 * The request to update a service
 * @export
 * @interface UpdateServiceRequest
 */
export interface UpdateServiceRequest {
    /**
     * The comment of the service
     * @type {string}
     * @memberof UpdateServiceRequest
     */
    comment?: string | null;
    /**
     * The global tags that are attached to the service
     * @type {Array<string>}
     * @memberof UpdateServiceRequest
     */
    globalTags?: Array<string> | null;
    /**
     * The workspace tags that are attached to the service
     * @type {Array<string>}
     * @memberof UpdateServiceRequest
     */
    workspaceTags?: Array<string> | null;
}

/**
 * Check if a given object implements the UpdateServiceRequest interface.
 */
export function instanceOfUpdateServiceRequest(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function UpdateServiceRequestFromJSON(json: any): UpdateServiceRequest {
    return UpdateServiceRequestFromJSONTyped(json, false);
}

export function UpdateServiceRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateServiceRequest {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'comment': !exists(json, 'comment') ? undefined : json['comment'],
        'globalTags': !exists(json, 'global_tags') ? undefined : json['global_tags'],
        'workspaceTags': !exists(json, 'workspace_tags') ? undefined : json['workspace_tags'],
    };
}

export function UpdateServiceRequestToJSON(value?: UpdateServiceRequest | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'comment': value.comment,
        'global_tags': value.globalTags,
        'workspace_tags': value.workspaceTags,
    };
}

