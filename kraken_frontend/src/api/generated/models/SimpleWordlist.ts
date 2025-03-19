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
 * A wordlist without its `path` field
 * @export
 * @interface SimpleWordlist
 */
export interface SimpleWordlist {
    /**
     * The primary key of the wordlist
     * @type {string}
     * @memberof SimpleWordlist
     */
    uuid: string;
    /**
     * The wordlist's name to be displayed select buttons
     * @type {string}
     * @memberof SimpleWordlist
     */
    name: string;
    /**
     * A description explaining the wordlist's intended use case
     * @type {string}
     * @memberof SimpleWordlist
     */
    description: string;
}

/**
 * Check if a given object implements the SimpleWordlist interface.
 */
export function instanceOfSimpleWordlist(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuid" in value;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "description" in value;

    return isInstance;
}

export function SimpleWordlistFromJSON(json: any): SimpleWordlist {
    return SimpleWordlistFromJSONTyped(json, false);
}

export function SimpleWordlistFromJSONTyped(json: any, ignoreDiscriminator: boolean): SimpleWordlist {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuid': json['uuid'],
        'name': json['name'],
        'description': json['description'],
    };
}

export function SimpleWordlistToJSON(value?: SimpleWordlist | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'uuid': value.uuid,
        'name': value.name,
        'description': value.description,
    };
}

