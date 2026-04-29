package com.mxr.integration.queryparser;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

@Slf4j
@Component
public class NaturalQueryParser {

    private static final Map<String, String> COUNTRY_MAP = new HashMap<>();

    static {
        COUNTRY_MAP.put("nigeria", "NG");
        COUNTRY_MAP.put("ghana", "GH");
        COUNTRY_MAP.put("kenya", "KE");
        COUNTRY_MAP.put("ethiopia", "ET");
        COUNTRY_MAP.put("tanzania", "TZ");
        COUNTRY_MAP.put("uganda", "UG");
        COUNTRY_MAP.put("angola", "AO");
        COUNTRY_MAP.put("south africa", "ZA");
        COUNTRY_MAP.put("cameroon", "CM");
        COUNTRY_MAP.put("senegal", "SN");
        COUNTRY_MAP.put("ivory coast", "CI");
        COUNTRY_MAP.put("cote d'ivoire", "CI");
        COUNTRY_MAP.put("mali", "ML");
        COUNTRY_MAP.put("niger", "NE");
        COUNTRY_MAP.put("burkina faso", "BF");
        COUNTRY_MAP.put("zimbabwe", "ZW");
        COUNTRY_MAP.put("zambia", "ZM");
        COUNTRY_MAP.put("mozambique", "MZ");
        COUNTRY_MAP.put("madagascar", "MG");
        COUNTRY_MAP.put("rwanda", "RW");
        COUNTRY_MAP.put("somalia", "SO");
        COUNTRY_MAP.put("sudan", "SD");
        COUNTRY_MAP.put("egypt", "EG");
        COUNTRY_MAP.put("morocco", "MA");
        COUNTRY_MAP.put("algeria", "DZ");
        COUNTRY_MAP.put("tunisia", "TN");
        COUNTRY_MAP.put("libya", "LY");
        COUNTRY_MAP.put("botswana", "BW");
        COUNTRY_MAP.put("namibia", "NA");
        COUNTRY_MAP.put("malawi", "MW");
        COUNTRY_MAP.put("benin", "BJ");
        COUNTRY_MAP.put("togo", "TG");
        COUNTRY_MAP.put("sierra leone", "SL");
        COUNTRY_MAP.put("liberia", "LR");
        COUNTRY_MAP.put("guinea", "GN");
        COUNTRY_MAP.put("guinea-bissau", "GW");
        COUNTRY_MAP.put("cape verde", "CV");
        COUNTRY_MAP.put("gambia", "GM");
        COUNTRY_MAP.put("mauritania", "MR");
        COUNTRY_MAP.put("eritrea", "ER");
        COUNTRY_MAP.put("djibouti", "DJ");
        COUNTRY_MAP.put("burundi", "BI");
        COUNTRY_MAP.put("gabon", "GA");
        COUNTRY_MAP.put("republic of the congo", "CG");
        COUNTRY_MAP.put("congo", "CG");
        COUNTRY_MAP.put("democratic republic of the congo", "CD");
        COUNTRY_MAP.put("central african republic", "CF");
        COUNTRY_MAP.put("chad", "TD");
        COUNTRY_MAP.put("equatorial guinea", "GQ");
        COUNTRY_MAP.put("sao tome", "ST");
        COUNTRY_MAP.put("comoros", "KM");
        COUNTRY_MAP.put("seychelles", "SC");
        COUNTRY_MAP.put("mauritius", "MU");
        COUNTRY_MAP.put("lesotho", "LS");
        COUNTRY_MAP.put("swaziland", "SZ");
        COUNTRY_MAP.put("eswatini", "SZ");
        COUNTRY_MAP.put("china", "CN");
        COUNTRY_MAP.put("india", "IN");
        COUNTRY_MAP.put("indonesia", "ID");
        COUNTRY_MAP.put("pakistan", "PK");
        COUNTRY_MAP.put("bangladesh", "BD");
        COUNTRY_MAP.put("philippines", "PH");
        COUNTRY_MAP.put("vietnam", "VN");
        COUNTRY_MAP.put("myanmar", "MM");
        COUNTRY_MAP.put("thailand", "TH");
        COUNTRY_MAP.put("malaysia", "MY");
    }

    public ParsedQuery parse(String query) {
        if (query == null || query.isBlank()) {
            throw new IllegalArgumentException("Query cannot be null or empty");
        }

        String q = query.toLowerCase().trim();
        ParsedQuery result = new ParsedQuery();
        boolean matched = false;

        boolean hasMale = q.contains("male") || q.contains("males") || q.contains("man") || q.contains("men")
                || q.contains("boy") || q.contains("boys");
        boolean hasFemale = q.contains("female") || q.contains("females") || q.contains("woman") || q.contains("women")
                || q.contains("girl") || q.contains("girls");
        boolean bothGenders = (hasMale && hasFemale) || q.contains("people") || q.contains("persons")
                || q.contains("profiles") || q.contains("users");

        if (!bothGenders) {
            if (hasMale) {
                result.setGender("male");
                matched = true;
            } else if (hasFemale) {
                result.setGender("female");
                matched = true;
            }
        } else if (q.contains("people") || q.contains("persons") || q.contains("profiles") || q.contains("users")) {
            matched = true;
        } else if (hasMale && hasFemale) {
            matched = true;
        }

        Matcher aboveMatcher = Pattern
                .compile("(?:above|over|older than|greater than)\\s+(\\d+)")
                .matcher(q);
        if (aboveMatcher.find()) {
            result.setMinAge(Integer.parseInt(aboveMatcher.group(1)));
            matched = true;
        }

        Matcher belowMatcher = Pattern
                .compile("(?:below|under|younger than|less than)\\s+(\\d+)")
                .matcher(q);
        if (belowMatcher.find()) {
            result.setMaxAge(Integer.parseInt(belowMatcher.group(1)));
            matched = true;
        }

        Matcher betweenMatcher = Pattern
                .compile("between\\s+(\\d+)\\s+and\\s+(\\d+)")
                .matcher(q);
        if (betweenMatcher.find()) {
            result.setMinAge(Integer.parseInt(betweenMatcher.group(1)));
            result.setMaxAge(Integer.parseInt(betweenMatcher.group(2)));
            matched = true;
        }

        if (result.getMinAge() == null && result.getMaxAge() == null) {
            if (q.contains("child") || q.contains("children") || q.contains("kids") || q.contains("kid")) {
                result.setAgeGroup("child");
                matched = true;
            } else if (q.contains("teenager") || q.contains("teenagers") || q.contains("teen") || q.contains("teens")
                    || q.contains("adolescent")) {
                result.setAgeGroup("teenager");
                matched = true;
            } else if (q.contains("adult") || q.contains("adults")) {
                result.setAgeGroup("adult");
                matched = true;
            } else if (q.contains("senior") || q.contains("seniors") || q.contains("elderly")
                    || q.contains("old people")) {
                result.setAgeGroup("senior");
                matched = true;
            }
        }

        if (q.contains("young") && result.getAgeGroup() == null && result.getMinAge() == null) {
            result.setMinAge(16);
            result.setMaxAge(24);
            matched = true;
        }

        Matcher countryMatcher = Pattern
                .compile("(?:from|in)\\s+([a-z][a-z'\\-]+)(?:\\s+(?:above|below|over|under|between|who|with|and|$)|$)")
                .matcher(q);
        if (countryMatcher.find()) {
            String countryToken = countryMatcher.group(1).trim();
            String iso = COUNTRY_MAP.get(countryToken);
            if (iso == null) {
                String normalizedToken = countryToken.replaceAll("[\\s-]+", "");
                for (Map.Entry<String, String> entry : COUNTRY_MAP.entrySet()) {
                    if (entry.getKey().replaceAll("[\\s-]+", "").equals(normalizedToken)) {
                        iso = entry.getValue();
                        break;
                    }
                }
            }
            if (iso != null) {
                result.setCountryId(iso);
                matched = true;
            }
        }

        if (!matched) {
            log.warn("Unable to parse query: {}", query);
            throw new IllegalArgumentException("Unable to interpret query: " + query);
        }

        log.debug("Parsed query: gender={}, ageGroup={}, countryId={}, minAge={}, maxAge={}",
                result.getGender(), result.getAgeGroup(), result.getCountryId(),
                result.getMinAge(), result.getMaxAge());

        return result;
    }
}
