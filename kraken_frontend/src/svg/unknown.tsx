import React from "react";

export default function UnknownIcon(props: React.HTMLAttributes<HTMLDivElement>) {
    return (
        <div className={"icon"} {...props}>
            <svg className="neon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                    fillRule="evenodd"
                    clipRule="evenodd"
                    d="M13.1557 11.7325C11.9132 12.6849 10.5 13.7681 10.5 16.5H13.5C13.5 14.8569 14.5665 13.9249 15.6611 12.9683C16.815 11.96 18 10.9244 18 9C18 5.685 15.315 3 12 3C8.685 3 6 5.685 6 9H9C9 7.35 10.35 6 12 6C13.65 6 15 7.35 15 9C15 10.3188 14.1304 10.9854 13.1557 11.7325ZM13.5 21.75V18.75H10.5V21.75H13.5Z"
                    fill="#000000"
                />
            </svg>
        </div>
    );
}
