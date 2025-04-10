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
import type { AggregationType } from './AggregationType';
import {
    AggregationTypeFromJSON,
    AggregationTypeFromJSONTyped,
    AggregationTypeToJSON,
} from './AggregationType';

/**
 * The request to add a new object affected by a finding
 * @export
 * @interface CreateFindingAffectedRequest
 */
export interface CreateFindingAffectedRequest {
    /**
     * The object's uuid
     * @type {string}
     * @memberof CreateFindingAffectedRequest
     */
    uuid: string;
    /**
     * 
     * @type {AggregationType}
     * @memberof CreateFindingAffectedRequest
     */
    type: AggregationType;
    /**
     * Notes about the finding included in the data export
     * 
     * May be used for documenting details about the finding
     * used to generate reports outside of kraken.
     * @type {string}
     * @memberof CreateFindingAffectedRequest
     */
    exportDetails: string;
    /**
     * Notes about the affected provided by the user
     * 
     * May be used for documenting command invocation or other information
     * that are provided by the user
     * @type {string}
     * @memberof CreateFindingAffectedRequest
     */
    userDetails: string;
    /**
     * A screenshot
     * 
     * The file must have been uploaded through the image upload.
     * @type {string}
     * @memberof CreateFindingAffectedRequest
     */
    screenshot?: string | null;
    /**
     * A log file
     * @type {string}
     * @memberof CreateFindingAffectedRequest
     */
    logFile?: string | null;
}

/**
 * Check if a given object implements the CreateFindingAffectedRequest interface.
 */
export function instanceOfCreateFindingAffectedRequest(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuid" in value;
    isInstance = isInstance && "type" in value;
    isInstance = isInstance && "exportDetails" in value;
    isInstance = isInstance && "userDetails" in value;

    return isInstance;
}

export function CreateFindingAffectedRequestFromJSON(json: any): CreateFindingAffectedRequest {
    return CreateFindingAffectedRequestFromJSONTyped(json, false);
}

export function CreateFindingAffectedRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): CreateFindingAffectedRequest {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuid': json['uuid'],
        'type': AggregationTypeFromJSON(json['type']),
        'exportDetails': json['export_details'],
        'userDetails': json['user_details'],
        'screenshot': !exists(json, 'screenshot') ? undefined : json['screenshot'],
        'logFile': !exists(json, 'log_file') ? undefined : json['log_file'],
    };
}

export function CreateFindingAffectedRequestToJSON(value?: CreateFindingAffectedRequest | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'uuid': value.uuid,
        'type': AggregationTypeToJSON(value.type),
        'export_details': value.exportDetails,
        'user_details': value.userDetails,
        'screenshot': value.screenshot,
        'log_file': value.logFile,
    };
}

