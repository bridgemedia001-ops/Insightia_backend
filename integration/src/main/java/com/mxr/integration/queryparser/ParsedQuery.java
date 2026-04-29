package com.mxr.integration.queryparser;

import lombok.Data;

@Data
public class ParsedQuery {
    private String gender;
    private String ageGroup;
    private String countryId;
    private Integer minAge;
    private Integer maxAge;
}
