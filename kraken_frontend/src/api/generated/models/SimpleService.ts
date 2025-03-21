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
import type { ServiceCertainty } from './ServiceCertainty';
import {
    ServiceCertaintyFromJSON,
    ServiceCertaintyFromJSONTyped,
    ServiceCertaintyToJSON,
} from './ServiceCertainty';

/**
 * A simple representation of a service
 * @export
 * @interface SimpleService
 */
export interface SimpleService {
    /**
     * The uuid of the service
     * @type {string}
     * @memberof SimpleService
     */
    uuid: string;
    /**
     * The name of the service
     * @type {string}
     * @memberof SimpleService
     */
    name: string;
    /**
     * The version of the service
     * @type {string}
     * @memberof SimpleService
     */
    version?: string | null;
    /**
     * 
     * @type {ServiceCertainty}
     * @memberof SimpleService
     */
    certainty: ServiceCertainty;
    /**
     * The host this service is linked to
     * @type {string}
     * @memberof SimpleService
     */
    host: string;
    /**
     * The port this service may linked to
     * @type {string}
     * @memberof SimpleService
     */
    port?: string | null;
    /**
     * The comment attached to the service
     * @type {string}
     * @memberof SimpleService
     */
    comment: string;
    /**
     * The workspace is service is linked to
     * @type {string}
     * @memberof SimpleService
     */
    workspace: string;
    /**
     * The point in time, the record was created
     * @type {Date}
     * @memberof SimpleService
     */
    createdAt: Date;
}

/**
 * Check if a given object implements the SimpleService interface.
 */
export function instanceOfSimpleService(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuid" in value;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "certainty" in value;
    isInstance = isInstance && "host" in value;
    isInstance = isInstance && "comment" in value;
    isInstance = isInstance && "workspace" in value;
    isInstance = isInstance && "createdAt" in value;

    return isInstance;
}

export function SimpleServiceFromJSON(json: any): SimpleService {
    return SimpleServiceFromJSONTyped(json, false);
}

export function SimpleServiceFromJSONTyped(json: any, ignoreDiscriminator: boolean): SimpleService {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuid': json['uuid'],
        'name': json['name'],
        'version': !exists(json, 'version') ? undefined : json['version'],
        'certainty': ServiceCertaintyFromJSON(json['certainty']),
        'host': json['host'],
        'port': !exists(json, 'port') ? undefined : json['port'],
        'comment': json['comment'],
        'workspace': json['workspace'],
        'createdAt': (new Date(json['created_at'])),
    };
}

export function SimpleServiceToJSON(value?: SimpleService | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'uuid': value.uuid,
        'name': value.name,
        'version': value.version,
        'certainty': ServiceCertaintyToJSON(value.certainty),
        'host': value.host,
        'port': value.port,
        'comment': value.comment,
        'workspace': value.workspace,
        'created_at': (value.createdAt.toISOString()),
    };
}

