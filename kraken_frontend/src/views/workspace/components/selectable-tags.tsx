import { SimpleTag, TagType } from "../../../api/generated";
import React from "react";
import { Api } from "../../../api/api";
import { handleApiError } from "../../../utils/helper";
import Select from "react-select";
import { selectStyles } from "../../../components/select-menu";
import Tag from "../../../components/tag";
import { WORKSPACE_CONTEXT } from "../workspace";

export type SelectableTagsProps = {
    /** List of currently set tags */
    tags: Array<SimpleTag>;

    /** Callback when the list changed */
    onChange: (tags: Array<SimpleTag>) => void;
};

/** A multi `<Select />` for selecting a list of tags */
export default function SelectableTags(props: SelectableTagsProps) {
    const { tags, onChange } = props;

    const {
        workspace: { uuid: workspace },
    } = React.useContext(WORKSPACE_CONTEXT);

    // Load tags from backend
    const [allTags, setAllTags] = React.useState<Array<SimpleTag>>([]);
    React.useEffect(() => {
        setAllTags([]);
        Api.globalTags
            .all()
            .then(
                handleApiError(({ globalTags }) =>
                    setAllTags((workspaceTags) => [
                        ...workspaceTags,
                        ...globalTags.map((tag) => ({ ...tag, tagType: TagType.Global })),
                    ]),
                ),
            );
        Api.workspaces.tags
            .all(workspace)
            .then(
                handleApiError(({ workspaceTags }) =>
                    setAllTags((globalTags) => [
                        ...workspaceTags.map((tag) => ({ ...tag, tagType: TagType.Workspace })),
                        ...globalTags,
                    ]),
                ),
            );
    }, [workspace]);

    return (
        <Select<SimpleTag, true>
            styles={selectStyles("default")}
            isMulti={true}
            value={tags}
            onChange={(tags) => onChange([...tags])}
            options={allTags}
            formatOptionLabel={Tag}
            getOptionLabel={({ name }) => name}
            getOptionValue={({ uuid }) => uuid}
        />
    );
}
