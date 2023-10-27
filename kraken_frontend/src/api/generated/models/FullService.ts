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
import type { Certainty } from './Certainty';
import {
    CertaintyFromJSON,
    CertaintyFromJSONTyped,
    CertaintyToJSON,
} from './Certainty';
import type { SimpleHost } from './SimpleHost';
import {
    SimpleHostFromJSON,
    SimpleHostFromJSONTyped,
    SimpleHostToJSON,
} from './SimpleHost';
import type { SimplePort } from './SimplePort';
import {
    SimplePortFromJSON,
    SimplePortFromJSONTyped,
    SimplePortToJSON,
} from './SimplePort';
import type { SimpleTag } from './SimpleTag';
import {
    SimpleTagFromJSON,
    SimpleTagFromJSONTyped,
    SimpleTagToJSON,
} from './SimpleTag';

/**
 * A full representation of a service
 * @export
 * @interface FullService
 */
export interface FullService {
    /**
     * 
     * @type {string}
     * @memberof FullService
     */
    uuid: string;
    /**
     * 
     * @type {string}
     * @memberof FullService
     */
    name: string;
    /**
     * 
     * @type {string}
     * @memberof FullService
     */
    version?: string | null;
    /**
     * 
     * @type {Certainty}
     * @memberof FullService
     */
    certainty: Certainty;
    /**
     * 
     * @type {SimpleHost}
     * @memberof FullService
     */
    host: SimpleHost;
    /**
     * 
     * @type {SimplePort}
     * @memberof FullService
     */
    port?: SimplePort | null;
    /**
     * 
     * @type {string}
     * @memberof FullService
     */
    comment: string;
    /**
     * 
     * @type {string}
     * @memberof FullService
     */
    workspace: string;
    /**
     * 
     * @type {Array<SimpleTag>}
     * @memberof FullService
     */
    tags: Array<SimpleTag>;
    /**
     * The point in time, the record was created
     * @type {Date}
     * @memberof FullService
     */
    createdAt: Date;
}

/**
 * Check if a given object implements the FullService interface.
 */
export function instanceOfFullService(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuid" in value;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "certainty" in value;
    isInstance = isInstance && "host" in value;
    isInstance = isInstance && "comment" in value;
    isInstance = isInstance && "workspace" in value;
    isInstance = isInstance && "tags" in value;
    isInstance = isInstance && "createdAt" in value;

    return isInstance;
}

export function FullServiceFromJSON(json: any): FullService {
    return FullServiceFromJSONTyped(json, false);
}

export function FullServiceFromJSONTyped(json: any, ignoreDiscriminator: boolean): FullService {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuid': json['uuid'],
        'name': json['name'],
        'version': !exists(json, 'version') ? undefined : json['version'],
        'certainty': CertaintyFromJSON(json['certainty']),
        'host': SimpleHostFromJSON(json['host']),
        'port': !exists(json, 'port') ? undefined : SimplePortFromJSON(json['port']),
        'comment': json['comment'],
        'workspace': json['workspace'],
        'tags': ((json['tags'] as Array<any>).map(SimpleTagFromJSON)),
        'createdAt': (new Date(json['created_at'])),
    };
}

export function FullServiceToJSON(value?: FullService | null): any {
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
        'certainty': CertaintyToJSON(value.certainty),
        'host': SimpleHostToJSON(value.host),
        'port': SimplePortToJSON(value.port),
        'comment': value.comment,
        'workspace': value.workspace,
        'tags': ((value.tags as Array<any>).map(SimpleTagToJSON)),
        'created_at': (value.createdAt.toISOString()),
    };
}

