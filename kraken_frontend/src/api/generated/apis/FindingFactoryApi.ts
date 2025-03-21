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


import * as runtime from '../runtime';
import type {
  ApiErrorResponse,
  GetFindingFactoryEntriesResponse,
  UpdateFindingFactoryEntryRequest,
} from '../models';
import {
    ApiErrorResponseFromJSON,
    ApiErrorResponseToJSON,
    GetFindingFactoryEntriesResponseFromJSON,
    GetFindingFactoryEntriesResponseToJSON,
    UpdateFindingFactoryEntryRequestFromJSON,
    UpdateFindingFactoryEntryRequestToJSON,
} from '../models';

export interface UpdateFindingFactoryEntryOperationRequest {
    updateFindingFactoryEntryRequest: UpdateFindingFactoryEntryRequest;
}

/**
 * 
 */
export class FindingFactoryApi extends runtime.BaseAPI {

    /**
     * An identifier is an enum variant which identifies one kind of issue, the finding factory might create a finding for.  If the finding factory detects an issue it will look up its identifier\'s finding definition and create a finding using this definition (if it found any).
     * Retrieves the current mapping between finding factory identifiers and finding definitions
     */
    async getFindingFactoryEntriesRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<GetFindingFactoryEntriesResponse>> {
        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/v1/admin/finding-factory/entries`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => GetFindingFactoryEntriesResponseFromJSON(jsonValue));
    }

    /**
     * An identifier is an enum variant which identifies one kind of issue, the finding factory might create a finding for.  If the finding factory detects an issue it will look up its identifier\'s finding definition and create a finding using this definition (if it found any).
     * Retrieves the current mapping between finding factory identifiers and finding definitions
     */
    async getFindingFactoryEntries(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<GetFindingFactoryEntriesResponse> {
        const response = await this.getFindingFactoryEntriesRaw(initOverrides);
        return await response.value();
    }

    /**
     * Updates a single finding factory identifier
     */
    async updateFindingFactoryEntryRaw(requestParameters: UpdateFindingFactoryEntryOperationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.updateFindingFactoryEntryRequest === null || requestParameters.updateFindingFactoryEntryRequest === undefined) {
            throw new runtime.RequiredError('updateFindingFactoryEntryRequest','Required parameter requestParameters.updateFindingFactoryEntryRequest was null or undefined when calling updateFindingFactoryEntry.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/v1/admin/finding-factory/entry`,
            method: 'PUT',
            headers: headerParameters,
            query: queryParameters,
            body: UpdateFindingFactoryEntryRequestToJSON(requestParameters.updateFindingFactoryEntryRequest),
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Updates a single finding factory identifier
     */
    async updateFindingFactoryEntry(requestParameters: UpdateFindingFactoryEntryOperationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.updateFindingFactoryEntryRaw(requestParameters, initOverrides);
    }

}
